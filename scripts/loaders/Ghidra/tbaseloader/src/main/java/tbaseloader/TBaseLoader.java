package tbaseloader;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class TBaseLoader extends AbstractLibrarySupportLoader {
    private static long BASE_ADDR = 0x7F00000;
    private static String VERSION = "t-base-EXYNOS64-Android-";

    private static long S0CB_ADDR = 0x7FFF000;
    private static List<String> TRUSTLETS = Arrays.asList("drcrypt", "drcrypto", "tlproxy", "sth2", "rpmb");

    private static class TableEntry {
        public String name;
        public long addr;
        public long size;
    }

    private long mclibAddr;
    private long tableAddr;
    private long fileOffset;

    private static long find(BinaryReader reader, byte[] pattern, long offset) throws IOException {
        for (long i = offset; i <= reader.length() - pattern.length; ++i) {
            for (int j = 0; j < pattern.length; ++j) {
                if (reader.readByte(i + j) != pattern[j])
                    break;
                if (j == pattern.length - 1)
                    return i;
            }
        }
        return -1;
    }

    private static long findPattern(BinaryReader reader, byte[] pattern, long align) throws IOException {
        long location = find(reader, pattern, 0);
        while (location != -1) {
            if (align == 0 || (location & (align - 1)) == 0)
                return location;
            location = find(reader, pattern, location + 1);
        }
        return location;
    }

    private static long findTable(BinaryReader reader) throws IOException {
        long addr = findPattern(reader, "t-base ".getBytes(), 0);
        if (addr < 0)
            addr = findPattern(reader, "tee ".getBytes(), 0);
        return addr;
    }

    private static long findVersion(BinaryReader reader) throws IOException {
        long candidate = findPattern(reader, VERSION.getBytes(), 0);
        candidate += VERSION.length();

        String version = reader.readAsciiString(candidate, 4);
        if (version.equals("200A") || version.equals("200B"))
            return 1;
        else if (version.equals("302A") || version.equals("310B"))
            return 4;
        else if (version.equals("400A"))
            return 5;
        return 0;
    }

    private List<TableEntry> parseTable(BinaryReader reader) throws IOException {
        List<TableEntry> table = new ArrayList<>();
        reader.setPointerIndex(tableAddr + 0x20);
        while (reader.peekNextByte() != (byte) 0) {
            TableEntry entry = new TableEntry();
            entry.name = reader.readNextAsciiString(8);
            entry.addr = reader.readNextUnsignedInt();
            entry.size = reader.readNextUnsignedInt();
            reader.readNextByteArray(16);
            table.add(entry);
        }
        return table;
    }

    private boolean askSaveBinaries() {
        String message = "Would you like to save the extracted binaries to disk?";
        int choice = OptionDialog.showYesNoDialog(null, "", message);
        return choice == OptionDialog.YES_OPTION;
    }

    private void extractBinary(BinaryReader reader, String name, long offset, long size) throws IOException {
        GhidraFileChooser chooser = new GhidraFileChooser(null);
        File directory = reader.getByteProvider().getFile().getParentFile();
        chooser.setSelectedFile(new File(directory, name));
        chooser.setTitle("Please enter a file name");
        File file = chooser.getSelectedFile(true);
        if (file != null)
            FileUtilities.writeBytes(file, reader.readByteArray(offset, (int) size));
    }

    private void mapSegments(BinaryReader reader, FlatProgramAPI api, List<TableEntry> table, boolean noSave)
            throws IOException {
        for (TableEntry entry : table) {
            Address start = api.toAddr(BASE_ADDR + entry.addr);
            boolean data = false, code = true;

            if (entry.name.equals("image_h") || entry.name.equals("img-hdr"))
                code = !(data = true);
            else if (entry.name.equals("mclib"))
                start = api.toAddr(mclibAddr - 8);
            else if (entry.name.equals("rtm"))
                start = api.toAddr(S0CB_ADDR);
            else if (TRUSTLETS.contains(entry.name)) {
                if (!noSave)
                    extractBinary(reader, entry.name + ".tlbin", fileOffset + entry.addr, entry.size);
                continue;
            } else if (!entry.name.equals("mtk")) {
                Msg.info(this, String.format("Unknown table entry '%s'", entry.name));
                continue;
            }

            InputStream input = reader.getByteProvider().getInputStream(fileOffset + entry.addr);
            try {
                MemoryBlock block = api.createMemoryBlock(entry.name, start, input, entry.size, false);
                block.setRead(code || data);
                block.setWrite(data);
                block.setExecute(code);
            } catch (Exception e) {
                Msg.error(this, e);
            }
            input.close();

            if (!noSave) {
                String filename = String.format("%s_%08x.bin", entry.name, start.getOffset());
                extractBinary(reader, filename, fileOffset + entry.addr, entry.size);
            }
        }
    }

    @Override
    public String getName() {
        return "<t-base image (sboot.bin)";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, true);

        long table = findTable(reader);
        if (table == -1)
            return new ArrayList<LoadSpec>();
        return List.of(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v7", "default"), true));
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
            TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
        BinaryReader reader = new BinaryReader(provider, true);
        FlatProgramAPI api = new FlatProgramAPI(program, monitor);

        long mclfAddr = findPattern(reader, "MCLF".getBytes(), 0x1000);
        if (mclfAddr == -1) {
            Msg.error(this, "MCLF header not found");
            return;
        }

        long rtmAddr = findPattern(reader, "S0CB".getBytes(), 0x1000);
        if (rtmAddr == -1) {
            Msg.error(this, "S0CB header not found");
            return;
        }

        mclibAddr = reader.readUnsignedInt(rtmAddr + 0x8c);

        tableAddr = findTable(reader);
        if (tableAddr == -1) {
            Msg.error(this, "Table header not found");
            return;
        }

        long offset = findVersion(reader);
        if (offset == -1) {
            Msg.error(this, "Table header not found");
            return;
        }

        fileOffset = mclfAddr - reader.readUnsignedInt(tableAddr + 0x20 * offset + 8);

        List<TableEntry> table = parseTable(reader);
        boolean noSave = !askSaveBinaries();
        mapSegments(reader, api, table, noSave);
    }
}

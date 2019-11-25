import re
import struct

import ida_idp
import ida_segment
import ida_kernwin

TABLE_MAGIC = b"tee     "
TABLE_MAGIC2 = b"t-base "

BASE_ADDR = 0x7F00000
VERSION = b"t-base-EXYNOS64-Android-(\w+)-[A-Za-z0-9-_]+"

S0CB_ADDR = 0x7FFF000
TRUSTLETS = [b"drcrypt", b"drcrypto", b"tlproxy", b"sth2", b"rpmb"]


def decode(s):
    """Decodes UTF-8 bytes into a unicode string."""
    if isinstance(s, str):
        return s
    return s.decode("utf-8")

def find_pattern(data, pattern, align=0):
    location = 0
    while True:
        location = data.find(pattern, location + 1)
        if location == -1:
            return None
        if align == 0 or location & (align - 1) == 0:
            return location


def find_table(d):
    addr = find_pattern(d, b"t-base ")
    if not addr:
        addr = find_pattern(d, b"tee    ")
    return addr


def find_version(d):
    offset = 0
    version = re.search(VERSION, d).group(1)
    if version in [b"200A", b"200B"]:
        offset = 1
    elif version in [b"302A", b"310B"]:
        offset = 4
    elif version in [b"400A"]:
        offset = 5
    return offset


def accept_file(li, filename):
    li.seek(0)
    d = li.read(li.size())

    addr = find_table(d)
    if addr:
        return "<t-base image (sboot.bin)"
    return 0


def parse_table(li, table_addr):
    li.seek(table_addr)
    bs = li.read(0x20)

    table = []
    while True:
        bs = li.read(0x20)
        if not struct.unpack("<Q", bs[0:8])[0]:
            break

        name = bs[0:8].strip(b"\x00").strip()
        addr = struct.unpack("<I", bs[8:12])[0]
        size = struct.unpack("<I", bs[12:16])[0]
        table.append((name, addr, size))
    return table


def ask_save_binaries(li):
    message = "Would you like to save the extracted binaries to disk?"
    choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, message)
    return choice == ida_kernwin.ASKBTN_YES


def extract_binary(li, name, offset, size):
    name = ida_kernwin.ask_file(True, decode(name), decode(b"Please enter a file name"))
    if name:
        with open(name, "wb") as f:
            li.seek(offset)
            f.write(li.read(size))


def map_segments(li, table, file_offset, mclib_addr, no_save):
    for name, addr, size in table:
        seg = ida_segment.segment_t()
        seg.start_ea = BASE_ADDR + addr
        sclass = "CODE"

        if name in [b"image_h", b"img-hdr"]:
            sclass = "DATA"
        elif name == b"mclib":
            seg.start_ea = mclib_addr - 8
        elif name == b"rtm":
            seg.start_ea = S0CB_ADDR
        elif name in TRUSTLETS:
            if not no_save:
                extract_binary(li, name + b".tlbin", file_offset + addr, size)
            continue
        elif name != b"mtk":
            ida_kernwin.info("Unknown table entry '%s'" % decode(name))
            continue

        seg.end_ea = seg.start_ea + size
        seg.bitness = 1
        ida_segment.add_segm_ex(seg, decode(name), sclass, 0)
        li.file2base(file_offset + addr, seg.start_ea, seg.end_ea - 1, 0)

        if not no_save:
            filename = b"%s_%08x.bin" % (name, seg.start_ea)
            extract_binary(li, filename, file_offset + addr, size)


def load_file(li, neflags, format):
    flags = ida_idp.SETPROC_LOADER_NON_FATAL | ida_idp.SETPROC_LOADER
    ida_idp.set_processor_type("arm", flags)

    li.seek(0)
    d = li.read(li.size())

    mclf_addr = find_pattern(d, b"MCLF", 0x1000)
    if not mclf_addr:
        ida_kernwin.warning("MCLF header not found")
        return 0

    rtm_addr = find_pattern(d, b"S0CB", 0x1000)
    if not rtm_addr:
        ida_kernwin.warning("S0CB header not found")
        return 0

    mclib_addr = struct.unpack("<I", d[rtm_addr + 0x8C:rtm_addr + 0x8C + 4])[0]

    table_addr = find_table(d)
    if not table_addr:
        ida_kernwin.warning("Table header not found")
        return 0

    offset = find_version(d)
    if not offset:
        ida_kernwin.warning("Unknown version string")
        return 0

    elem = d[table_addr + 0x20 * offset:table_addr + 0x20 * (offset + 1)]
    file_offset = mclf_addr - struct.unpack("<I", elem[8:12])[0]

    table = parse_table(li, table_addr)
    no_save = not ask_save_binaries(li)
    map_segments(li, table, file_offset, mclib_addr, no_save)
    return 1

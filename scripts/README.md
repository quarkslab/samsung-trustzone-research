# Scripts

Here are the various IDA Pro/Ghidra extensions that we have developed.

## Loaders

## MCLF loader

The MCLF loader allows loading trustlet/driver binaries in the MCLF file format.

It parses the header, maps the segments, sets the entry point and renames the mcLib handler.

- IDA Pro version is at `loaders/IDAPro/mclf_loader.py`
- Ghidra version is in `loaders/Ghidra/mclfloader`

## <t-base loader

The <t-base loader allows loading the various components contained in the SBOOT binary.

The embedded trustlets and driver can be extracted to disk via the built-in dialogs.

- IDA Pro version is at `loaders/IDAPro/tbase_loader.py`
- Ghidra version is in `loaders/Ghidra/tbaseloader`

## Scripts

## Find Symbols

This scripts will find the stubs in the trustlet and driver binaries, extract the tlApi/drApi number, and rename and set the prototype of the corresponding function.

- IDA Pro version is at `scripts/IDAPro/find_symbols.py`
- Ghidra version is at `scripts/Ghidra/FindSymbols.py`

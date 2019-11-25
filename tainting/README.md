# Tainting

This is a little experiment using [Manticore](https://github.com/trailofbits/manticore) to perform symbolic execution of trustlets. On memory accesses, by asking the solver if it is possible to obtain an invalid address, we can detect potential vulnerabilities.

## Installation

### Installing Manticore

You'll need to install the development version of Manticore.

```
git clone https://github.com/trailofbits/manticore
cd manticore
python -m pip install -e .
```

## Usage

### Converting a trustlet

Manticore supports ELF files out of the box, so we will first convert our trustlets from MCLF to ELF.

```
python mclf2elf/mclf2elf.py <trustlet>
```

### Tainting a trustlet

Then we can use the script to perform the symbolic execution of the trustlet binary.

```
python tainter.py -s <buffer_size> <trustlet>.elf
```

Note: use `-v` to display Manticore debug messages.

### Exporting coverage

Use the `-c` flag to write coverage to a file on the disk.

Use [Lighthouse](https://github.com/gaasedelen/lighthouse) to display coverage into IDA Pro.

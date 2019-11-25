# Bindings

## Introduction

Python bindings for `libMcClient.so`, the library that is used to communicate with Trusted Applications and Secure Drivers. The bindings can be used as a library, or we also offer a very practical REPL which is based on IPython.

## Installation

First you will need to install Python 3 on your device. To do that we suggest you use the [`python3-android`](https://github.com/yan12125/python3-android) project by @[yan12125](https://github.com/yan12125). Then you can install `pip` on it using [`get-pip.py`](https://bootstrap.pypa.io/get-pip.py) and finally install IPython itself.

If you're interested in compiling Keystone/Capstone for Android, check out [this guide](COMPILING.md).

Installation of the project can be done from the sources

```
$ python setup.py install
```

## Usage

To start the REPL, simply enter

```
$ pymcclient
```

## Example

```python
from mcclient import *

# Create a device session
with Device() as dev:

    # Allocate a TCI buffer
    with dev.buffer(tci_size) as tci:

        # Create a trustlet session
        with Trustlet.uuid(dev, tci, uuid) as app:

            # Write the command ID
            tci.seek(0)
            tci.write_dword(42)

            # Notify the trustlet
            app.notify()
            # Wait for a notification
            app.wait_notification()

            # Display the TCI buffer
            tci.seek(0)
            tci.hexdump(0x100)
```

Thanks to Python's context managers, the sessions are automatically closed and the buffers automatically freed when the "with statements" are exited.

But you can still go the old fashioned way and call the `open` and `close` methods yourself.

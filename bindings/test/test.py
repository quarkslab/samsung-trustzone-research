from mcclient import *

DEVICE_ID = DEVICE_ID_DEFAULT
TCI_BUFFER_SIZE = 0x1000

TRUSTLET_UUID = "ffffffff00000000000000000000000e"
TRUSTLET_FILE = "/system/app/mcRegistry/%s.tlbin" % TRUSTLET_UUID


def main():
    with Device(DEVICE_ID) as dev:
        print(dev.id)
        print(dev.version())

        with dev.buffer(TCI_BUFFER_SIZE) as tci:
            with open(TRUSTLET_FILE, "rb") as fd:
                buf = fd.read()

            with Trustlet(dev, tci, buf) as app:
                print(app.id)
                print(app.error())

                buf = dev.alloc(0x42)
                with app.share(buf) as info:
                    print(info)
                dev.free(buf)

                tci.seek(0)
                tci.write_dword(1)

                app.notify()
                app.wait_notification()

                tci.seek(0)
                print(tci.read_dword())


if __name__ == "__main__":
    main()

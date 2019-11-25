import ctypes
import io
import os
import struct
import sys

from contextlib import contextmanager

from . import mcclient_const as const
from . import mcclient_types as types


if 'sphinx' in sys.modules:
    client = None
else:
    client = types.load_library()
    if client is None:
        raise ImportError("ERROR: fail to load the dynamic library.")


class Error(Exception):
    """
    This exception is raised when a function doesn't return successfully.
    """
    def __init__(self, code):
        self._code = code

    @property
    def code(self):
        """
        The error code returned by the function.
        """
        return self._code

    def __str__(self):
        special = ["NO_NOTIFICATION", "INFO_NOTIFICATION"]
        for name in dir(const):
            if getattr(const, name) == self._code \
                    and (name.startswith("ERR_") or name in special):
                return name
        return "ERR_UNKNOWN"


class Device(object):
    """
    Initialize a session with a t-base device.

    Args:
        device_id (:obj:`int`): Identifier for the t-base device to be used.
                                DEVICE_ID_DEFAULT refers to the default device.

    This class can be used with a Python "with statement", meaning that it will
    automatically call :func:`Device.open` on enter and :func:`Device.close` on
    exit. ::

        with Device() as dev:
            # do something with the device
    """

    def __init__(self, id=const.DEVICE_ID_DEFAULT):
        self._id = id

    @property
    def id(self):
        """
        The identifier for the t-base device used.
        """
        return self._id

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()
        return False

    def open(self):
        """
        Open a new connection to a t-base device.

        It initializes all device specific resources required to communicate
        with an t-base instance located on the specified device in the system.

        Raises:
            :class:`Error`: See below the possible error codes:

                - ERR_INVALID_OPERATION if device already opened
                - ERR_DAEMON_UNREACHABLE when problems with daemon occur
                - ERR_UNKNOWN_DEVICE when device_id is unknown
                - ERR_INVALID_DEVICE_FILE if kernel module under /dev/mobicore
                  cannot be opened
        """
        res = client.mcOpenDevice(self._id)
        if res != const.OK:
            raise Error(res)

    def close(self):
        """
        Close the connection to a t-base device.

        When closing a device, active sessions have to be closed beforehand.
        Resources associated with the device will be released. The device may
        be opened again after it has been closed.

        Raises:
            :class:`Error`: See below the possible error codes:

                - ERR_UNKNOWN_DEVICE when device id is invalid
                - ERR_SESSION_PENDING when a session is still open
                - ERR_DAEMON_UNREACHABLE when problems with daemon occur
        """
        res = client.mcCloseDevice(self._id)
        if res != const.OK:
            raise Error(res)

    @contextmanager
    def buffer(self, len):
        """
        Instantiate a new memory buffer.

        Args:
            len (:obj:`int`): Length of the block in bytes

        Yields:
            :class:`Buffer`: The allocated block of memory

        This method can be used with a Python "with statement", meaning that it
        will automatically call :func:`Device.malloc` on enter and
        :func:`Device.free` on exit. ::

            with dev.buffer(0x1000) as tci:
                # do something with the buffer
        """
        buf = self.malloc(len)
        yield buf
        self.free(buf)

    def malloc(self, len):
        """
        Allocate a block of memory.

        The driver allocates a contiguous block of memory which can be used as
        WSM. This implicates that the allocated memory is always aligned to 4K.

        Args:
            len (:obj:`int`): Length of the block in bytes

        Returns:
            :class:`Buffer`: The allocated block of memory

        Raises:
            :class:`Error`: See below the possible error codes:

                - INVALID_PARAMETER if a parameter is invalid
                - ERR_UNKNOWN_DEVICE when device id is invalid
                - ERR_NO_FREE_MEMORY if no more contiguous memory is available
                  in this size or for this process
        """
        buf = ctypes.POINTER(ctypes.c_uint8)()
        res = client.mcMallocWsm(self._id, 0, len, ctypes.byref(buf), 0)
        if res != const.OK:
            raise Error(res)
        ptr = ctypes.cast(buf, ctypes.c_void_p)
        return Buffer(ptr, len)

    def free(self, buf):
        """
        Free a block of memory.

        The driver will free a block of memory previously allocated.

        Args:
            buf (:class:`Buffer`): The memory block to be freed

        Raises:
            :class:`Error`: See below the possible error codes:

                - INVALID_PARAMETER if a parameter is invalid
                - ERR_UNKNOWN_DEVICE when device id is invalid
                - ERR_FREE_MEMORY_FAILED on failures
        """
        ptr = ctypes.cast(buf._ptr, ctypes.POINTER(ctypes.c_uint8))
        res = client.mcFreeWsm(self._id, ptr)
        if res != const.OK:
            raise Error(res)
        buf.close()

    def version(self):
        """
        Get t-base version information of a device.

        Returns:
            :obj:`dict`: t-base version info
            ::

                {
                    'productId': b't-base-EXYNOS64-Android-302A-V015-681_681',
                    'versionMci': 65536,
                    'versionSo': 131074,
                    'versionMclf': 131077,
                    'versionContainer': 131073,
                    'versionMcConfig': 2,
                    'versionTlApi': 65552,
                    'versionDrApi': 65538,
                    'versionCmp': 0
                }

        Raises:
            :class:`Error`: See below the possible error codes:

                - ERR_UNKNOWN_DEVICE when device is not open
                - INVALID_PARAMETER if a parameter is invalid
                - ERR_DAEMON_UNREACHABLE when problems with daemon occur
        """
        info = types.mcVersionInfo()
        res = client.mcGetMobiCoreVersion(self._id, ctypes.byref(info))
        if res != const.OK:
            raise Error(res)
        return dict(info)


class Trustlet(object):
    """
    Initialize a session to a Trusted Application.

    Args:
        dev (:class:`Device`): The t-base device to use
        tci (:class:`Buffer`): TCI buffer for communicating with the TA
        buf (:obj:`bytes`): Buffer containing the TA binary

    This class can be used with a Python "with statement", meaning that it will
    automatically call :func:`Trustlet.open` on enter and
    :func:`Trustlet.close` on exit. ::

        with Trustlet(dev, tci, buf) as app:
            # do something with the trustlet
    """

    @staticmethod
    def uuid(dev, tci, uuid):
        """
        Initialize a session to a TA using its UUID.

        Args:
            dev (:class:`Device`): The t-base device to use
            tci (:class:`Buffer`): TCI buffer for communicating with the TA
            buf (:obj:`str`): The Trusted Application's UUID

        Returns:
            :class:`Trustlet`: A Trusted Application session
        """
        path = "/vendor/app/mcRegistry/{}.tlbin".format(uuid)
        if not os.path.exists(path):
            path = "/system/app/mcRegistry/{}.tlbin".format(uuid)
        if not os.path.exists(path):
            raise IOError("Could not find the trustlet")
        with open(path, "rb") as fd:
            return Trustlet(dev, tci, fd.read())

    def __init__(self, dev, tci, buf):
        self._ses = types.mcSessionHandle()
        self._ses.device_id = dev.id
        self._tci = tci
        self._buf = buf

    @property
    def id(self):
        """
        The identifier of the Trusted Application session.
        """
        return self._ses.sessionId

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()
        return False

    def open(self):
        """
        Open a new session to a Trusted Application (Trustlet). The trustlet
        will be loaded from the memory buffer.

        Write MCP open message to buffer and notify t-base about the
        availability of a new command. Waits till t-base responds with the new
        session ID (stored in the MCP buffer).

        Raises:
            :class:`Error`: See below the possible error codes:

                - INVALID_PARAMETER if session parameter is invalid
                - ERR_UNKNOWN_DEVICE when device id is invalid
                - ERR_DAEMON_UNREACHABLE when problems with daemon socket occur
                - ERR_UNKNOWN_DEVICE when daemon returns an error
                - ERR_TRUSTED_APPLICATION_NOT_FOUND when TA cannot be loaded
        """
        ta = (ctypes.c_uint8 * len(self._buf)).from_buffer_copy(self._buf)
        ta_ptr = ctypes.cast(ta, ctypes.POINTER(ctypes.c_uint8))
        tci_ptr = ctypes.cast(self._tci._ptr, ctypes.POINTER(ctypes.c_uint8))
        res = client.mcOpenTrustlet(ctypes.byref(self._ses), 0, ta_ptr,
                                    len(self._buf), tci_ptr, self._tci._len)
        if res != const.OK:
            raise Error(res)

    def close(self):
        """
        Close a Trusted Application session.

        Closes the specified t-base session. The call will block until the
        session has been closed.

        Raises:
            :class:`Error`: See below the possible error codes:

                - INVALID_PARAMETER if session parameter is invalid
                - ERR_UNKNOWN_SESSION when session id is invalid
                - ERR_UNKNOWN_DEVICE when device id of session is invalid
                - ERR_DAEMON_UNREACHABLE when problems with daemon occur
                - ERR_INVALID_DEVICE_FILE when daemon cannot open trustlet file
        """
        res = client.mcCloseSession(ctypes.byref(self._ses))
        if res != const.OK:
            raise Error(res)

    def notify(self):
        """
        Notify a session.

        Notifies the session end point about available message data.
        Corresponding errors can only be received by
        :func:`Trustlet.wait_notification`. A session has to be opened in
        advance.

        Raises:
            :class:`Error`: See below the possible error codes:

                - DRV_INVALID_PARAMETER if session parameter is invalid
                - DRV_ERR_UNKNOWN_SESSION when session id is invalid
                - DRV_ERR_UNKNOWN_DEVICE when device id of session is invalid
        """
        res = client.mcNotify(self._ses)
        if res != const.OK:
            raise Error(res)

    def wait_notification(self, timeout=const.INFINITE_TIMEOUT):
        """
        Wait for a notification.

        Wait for a notification issued by t-base for a specific session. The
        timeout parameter specifies the number of milliseconds the call will
        wait for a notification. If the caller passes 0 as timeout value the
        call will immediately return. If timeout value is below 0 the call will
        block until a notification for the session has been received.

        Warning:
            If timeout is below 0, the call will block. Caller has to trust the
            other side to send a notification to wake him up again.

        Args:
            timeout (:obj:`int`): Time in milliseconds to wait

        Raises:
            :class:`Error`: See below the possible error codes:

                - ERR_TIMEOUT if no notification arrived in time
                - INFO_NOTIFICATION if a problem with the session was
                  encountered. Get more details with :func:`Trustlet.error()`.
                - ERR_NOTIFICATION if a problem with the socket occurred
                - INVALID_PARAMETER if a parameter is invalid
                - ERR_UNKNOWN_SESSION when session id is invalid
                - ERR_UNKNOWN_DEVICE when device id of session is invalid
        """
        res = client.mcWaitNotification(ctypes.byref(self._ses), timeout)
        if res != const.OK:
            raise Error(res)

    @contextmanager
    def share(self, buf):
        """
        Share an additional buffer with the Trusted Application.

        Args:
            buf (:class:`Buffer`): Memory buffer to be shared with the TA

        Yields:
            :obj:`dict`: Information about the mapped bulk buffer
            ::

                {
                    'sVirtualAddr': 9437184,
                    'sVirtualLen': 4096
                }

        This method can be used with a Python "with statement", meaning that it
        will automatically call :func:`Trustlet.map` on enter and
        :func:`Trustlet.unmap` on exit. ::

            with app.share(buf):
                # do something with the additional buffer
        """
        map = self.map(buf)
        yield map
        self.unmap(buf, map)

    def map(self, buf):
        """
        Map additional bulk buffer between a Client Application (CA) and the
        Trusted Application (TA) for a session.

        Memory allocated in user space of the CA can be mapped as additional
        communication channel (besides TCI) to the Trusted Application.
        Limitation of the Trusted Application memory structure apply: only 6
        chunks can be mapped with a maximum chunk size of 1 MiB each.

        Warning:
            It is up to the application layer (CA) to inform the Trusted
            Application about the additional mapped bulk memory.

        Args:
            buf (:class:`Buffer`): Memory buffer to be shared with the TA

        Returns:
            :obj:`dict`: Information about the mapped bulk buffer
            ::

                {
                    'sVirtualAddr': 9437184,
                    'sVirtualLen': 4096
                }

        Raises:
            :class:`Error`: See below the possible error codes:

                - INVALID_PARAMETER if a parameter is invalid
                - ERR_UNKNOWN_SESSION when session id is invalid
                - ERR_UNKNOWN_DEVICE when device id of session is invalid
                - ERR_DAEMON_UNREACHABLE when problems with daemon occur
                - ERR_BULK_MAPPING when buf is already uses as bulk buffer or
                  when registering the buffer failed
        """
        info = types.mcBulkMap()
        res = client.mcMap(ctypes.byref(self._ses), buf._ptr, buf._len,
                           ctypes.byref(info))
        if res != const.OK:
            raise Error(res)
        return dict(info)

    def unmap(self, buf, info):
        """
        Remove additional mapped bulk buffer between Client Application (CA)
        and the Trusted Application (TA) for a session.

        Warning:
            The bulk buffer will immediately be unmapped from the session
            context. The application layer (CA) must inform the TA about
            unmapping of the additional bulk memory before making this call.

        Args:
            buf (:class:`Buffer`): Memory buffer shared with the TA
            info (:obj:`dict`): Information about the mapped bulk buffer

        Raises:
            :class:`Error`: See below the possible error codes:

                - INVALID_PARAMETER if a parameter is invalid
                - ERR_UNKNOWN_SESSION when session id is invalid
                - ERR_UNKNOWN_DEVICE when device id of session is invalid
                - ERR_DAEMON_UNREACHABLE when problems with daemon occur
                - ERR_BULK_MAPPING when buf was not registered earlier or when
                  unregistering failed
        """
        info = types.mcBulkMap(info)
        res = client.mcUnmap(ctypes.byref(self._ses), buf._ptr,
                             ctypes.byref(info))
        if res != const.OK:
            raise Error(res)

    def error(self):
        """
        Get additional error information of the last error that occurred on a
        session.

        After the request the stored error code will be deleted.

        Returns:
            :obj:`int`: >0 Trusted Application has terminated itself with
            this value, <0 Trusted Application is dead because of an error
            within t-base (e.g. Kernel exception)
        """
        err = ctypes.c_int32()
        res = client.mcGetSessionErrorCode(ctypes.byref(self._ses),
                                           ctypes.byref(err))
        if res != const.OK:
            raise Error(res)
        return err.value


class Buffer(io.RawIOBase):
    """
    This class exposes a memory memory buffer as a raw I/O stream object. It
    use provide convenience functions to read/write common data types.

    Warning:
        The constructor of this class should never be called directly. If you
        need to allocate a new buffer, use :func:`Device.malloc` instead.
    """

    def __init__(self, ptr, len):
        self._ptr = ptr
        self._len = len
        self._pos = 0

    def seek(self, offset, whence=0):
        self._checkClosed()
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self._len + offset
        self._pos = max(0, min(self._len, self._pos))
        return self._pos

    def truncate(self, size=None):
        self._checkClosed()
        if size is None:
            size = self._pos
        self._len = max(0, size)
        self.seek(self._pos)
        return self._len

    def seekable(self):
        return True

    def readinto(self, b):
        self._checkClosed()
        addr = self._ptr.value + self._pos
        size = min(self._len, self._pos + len(b)) - self._pos
        b[:size] = (ctypes.c_char * size).from_address(addr).raw
        self._pos += size
        return size

    def readable(self):
        return True

    def write(self, b):
        self._checkClosed()
        addr = self._ptr.value + self._pos
        size = min(self._len, self._pos + len(b)) - self._pos
        (ctypes.c_char * size).from_address(addr).raw = b[:size]
        self._pos += size
        return size

    def writable(self):
        return True

    def skip(self, size):
        """
        Move stream position forward of size bytes.

        Args:
            size (:obj:`int`): Number of bytes to skip
        """
        self.seek(size, io.SEEK_CUR)

    def read_byte(self, signed=False):
        """
        Read the byte at the current position.

        Args:
            signed (:obj:`bool`): Interpret as signed

        Returns:
            :obj:`int`: The value read
        """
        fmt = "<b" if signed else "<B"
        return struct.unpack(fmt, self.read(1))[0]

    def read_word(self, signed=False):
        """
        Read the word (2-byte long) value at the current position.

        Args:
            signed (:obj:`bool`): Interpret as signed

        Returns:
            :obj:`int`: The value read
        """
        fmt = "<h" if signed else "<H"
        return struct.unpack(fmt, self.read(2))[0]

    def read_dword(self, signed=False):
        """
        Read the double word (4-byte long) value at the current position.

        Args:
            signed (:obj:`bool`): Interpret as signed

        Returns:
            :obj:`int`: The value read
        """
        fmt = "<i" if signed else "<I"
        return struct.unpack(fmt, self.read(4))[0]

    def read_qword(self, signed=False):
        """
        Read the quadro word (8-byte long) value at the current position.

        Args:
            signed (:obj:`bool`): Interpret as signed

        Returns:
            :obj:`int`: The value read
        """
        fmt = "<q" if signed else "<Q"
        return struct.unpack(fmt, self.read(8))[0]

    def read_float(self):
        """
        Read the float (4-byte long) value at the current position.

        Returns:
            :obj:`float`: The value read
        """
        return struct.unpack("<f", self.read(4))[0]

    def read_double(self):
        """
        Read the double (8-byte long) value at the current position.

        Returns:
            :obj:`float`: The value read
        """
        return struct.unpack("<d", self.read(8))[0]

    def read_string(self):
        """
        Read the NULL-terminated string at the current position.


        Returns:
            :obj:`str`: The string read
        """
        val = b""
        c = self.read(1)
        while c != b"\x00":
            val += c
            c = self.read(1)
        return val

    def write_byte(self, val, signed=False):
        """
        Write a byte at the current position.

        Args:
            val (:class:`int`): The value to write
            signed (:obj:`bool`): Interpret as signed
        """
        fmt = "<b" if signed else "<B"
        self.write(struct.pack(fmt, val))

    def write_word(self, val, signed=False):
        """
        Write a word (2-byte long) at the current position.

        Args:
            val (:class:`int`): The value to write
            signed (:obj:`bool`): Interpret as signed
        """
        fmt = "<h" if signed else "<H"
        self.write(struct.pack(fmt, val))

    def write_dword(self, val, signed=False):
        """
        Write a double word (4-byte long) at the current position.

        Args:
            val (:class:`int`): The value to write
            signed (:obj:`bool`): Interpret as signed
        """
        fmt = "<i" if signed else "<I"
        self.write(struct.pack(fmt, val))

    def write_qword(self, val, signed=False):
        """
        Write a quadro word (8-byte long) at the current position.

        Args:
            val (:class:`int`): The value to write
            signed (:obj:`bool`): Interpret as signed
        """
        fmt = "<q" if signed else "<Q"
        self.write(struct.pack(fmt, val))

    def write_float(self, val):
        """
        Write a float (4-byte long) value at the current position.

        Args:
            val (:class:`float`): The value to write
        """
        self.write(struct.pack("<f", val))

    def write_double(self, val):
        """
        Write a double (8-byte long) value at the current position.

        Args:
            val (:class:`float`): The value to write
        """
        self.write(struct.pack("<d", val))

    def write_string(self, val):
        """
        Write a NULL-terminated string at the current position.

        Args:
            val (:obj:`str`): The string to write
        """
        self.write(val)
        self.write(b"\x00")

    def hexdump(self, size=-1):
        """
        Display an hex dump of the size bytes at the current position.

        Args:
            size (:obj:`int`): The number of bytes to dump (-1 = all)
        """
        if size == -1:
            size = self._len - self._pos
        for i in range(0, size, 0x10):
            hex_dmp = "0x{:08x}:".format(i)
            chr_dmp = " | "
            for j in range(min(0x10, size - i)):
                hex_chr = self.read(1)[0]
                hex_dmp += " {:02x}".format(hex_chr)
                if 0x20 <= hex_chr <= 0x7E:
                    chr_dmp += chr(hex_chr)
                else:
                    chr_dmp += "."
            hex_dmp = hex_dmp.ljust(60, " ")
            print(hex_dmp + chr_dmp)

    def assemble(self, code, thumb=True):
        """
        Assemble code using Keystone and write it at the current position.

        Args:
            code (:obj:`str`): the code to assemble
            thumb (:obj:`bool`): True if Thumb, False otherwise

        Returns:
            :obj:`int`: the number of bytes written
        """
        from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB

        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB if thumb else KS_MODE_ARM)

        addr = self._ptr.value
        bs, size = ks.asm(code, addr)
        self.write(bytes(bytearray(bs)))
        return len(bs)

    def disassemble(self, size, thumb=True):
        """
        Display the bytes disassembled using Capstone at the current position.

        Args:
            size (:obj:`int`): the number of bytes to disassemble
            thumb (:obj:`bool`): True if Thumb, False otherwise
        """
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)

        addr = self._ptr.value
        for insn in cs.disasm(self.read(size), addr):
            insn_info = insn.address, insn.mnemonic, insn.op_str
            print("{:08x}:\t{} {}".format(insn_info))

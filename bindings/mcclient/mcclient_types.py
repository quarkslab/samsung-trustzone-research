import ctypes
import os


mcResult = ctypes.c_uint32


class mcStructure(ctypes.Structure):

    def __init__(self, values=None):
        super(mcStructure, self).__init__()
        if values:
            for field, value in values.items():
                setattr(self, field, value)

    def __iter__(self):
        for field, _ in self._fields_:
            value = getattr(self, field)
            yield field, value


class mcSessionHandle(mcStructure):
    _fields_ = [("sessionId", ctypes.c_uint32), ("deviceId", ctypes.c_uint32)]


class mcUuid(mcStructure):
    _fields_ = [("value", ctypes.c_uint8 * 16)]


mcSpid = ctypes.c_uint32


class mcBulkMap(mcStructure):
    _fields_ = [
        ("sVirtualAddr", ctypes.c_uint32),
        ("sVirtualLen", ctypes.c_uint32),
    ]


class mcVersionInfo(mcStructure):
    _fields_ = [
        ("productId", ctypes.c_char * 64),
        ("versionMci", ctypes.c_uint32),
        ("versionSo", ctypes.c_uint32),
        ("versionMclf", ctypes.c_uint32),
        ("versionContainer", ctypes.c_uint32),
        ("versionMcConfig", ctypes.c_uint32),
        ("versionTlApi", ctypes.c_uint32),
        ("versionDrApi", ctypes.c_uint32),
        ("versionCmp", ctypes.c_uint32),
    ]


def load_library():
    mc_client = None
    for path in ["/system/lib64", "/system/lib",
                 "/vendor/lib64", "/vendor/lib"]:
        file_path = os.path.join(path, "libMcClient.so")
        if os.path.isfile(file_path):
            mc_client = ctypes.CDLL(file_path)
            break
    else:
        return None

    def setup_prototype(library, function, restype, *argtypes):
        getattr(library, function).restype = restype
        getattr(library, function).argtypes = argtypes

    setup_prototype(
        mc_client,
        "mcOpenDevice",
        mcResult,
        ctypes.c_uint32)
    setup_prototype(
        mc_client,
        "mcCloseDevice",
        mcResult,
        ctypes.c_uint32)

    setup_prototype(
        mc_client,
        "mcOpenSession",
        mcResult,
        ctypes.POINTER(mcSessionHandle),
        ctypes.POINTER(mcUuid),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint32,
    )
    setup_prototype(
        mc_client,
        "mcOpenTrustlet",
        mcResult,
        ctypes.POINTER(mcSessionHandle),
        mcSpid,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint32,
    )
    setup_prototype(
        mc_client,
        "mcCloseSession",
        mcResult,
        ctypes.POINTER(mcSessionHandle)
    )

    setup_prototype(
        mc_client,
        "mcNotify",
        mcResult,
        ctypes.POINTER(mcSessionHandle)
    )
    setup_prototype(
        mc_client,
        "mcWaitNotification",
        mcResult,
        ctypes.POINTER(mcSessionHandle),
        ctypes.c_uint32,
    )

    setup_prototype(
        mc_client,
        "mcMallocWsm",
        mcResult,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
        ctypes.c_uint32,
    )
    setup_prototype(
        mc_client,
        "mcFreeWsm",
        mcResult,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint8),
    )

    setup_prototype(
        mc_client,
        "mcMap",
        mcResult,
        ctypes.POINTER(mcSessionHandle),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(mcBulkMap),
    )
    setup_prototype(
        mc_client,
        "mcUnmap",
        mcResult,
        ctypes.POINTER(mcSessionHandle),
        ctypes.c_void_p,
        ctypes.POINTER(mcBulkMap),
    )

    setup_prototype(
        mc_client,
        "mcGetSessionErrorCode",
        mcResult,
        ctypes.POINTER(mcSessionHandle),
        ctypes.POINTER(ctypes.c_int32),
    )
    setup_prototype(
        mc_client,
        "mcGetMobiCoreVersion",
        mcResult,
        ctypes.c_uint32,
        ctypes.POINTER(mcVersionInfo),
    )

    return mc_client

.. include:: ../README.rst

Reference
=========

Error
-----

.. autoclass:: mcclient.Error
    :members:
    :undoc-members:
    :show-inheritance:

Device
------

.. autoclass:: mcclient.Device
    :members:
    :undoc-members:
    :show-inheritance:

Trustlet
-----------

.. autoclass:: mcclient.Trustlet
    :members:
    :undoc-members:
    :show-inheritance:

Buffer
------

.. autoclass:: mcclient.Buffer
    :members:
    :undoc-members:
    :show-inheritance:

Constants
---------

.. data:: mcclient.DEVICE_ID_DEFAULT = 0

    The default device ID

.. data:: mcclient.INFINITE_TIMEOUT = -1

    Wait infinite for a response of the MC

.. data:: mcclient.INFINITE_TIMEOUT_INTERRUPTIBLE = -2

    Wait infinite for a response of the MC, exit on signal

.. data:: mcclient.NO_TIMEOUT = 0

    Do not wait for a response of the MC

.. data:: mcclient.MAX_TCI_LEN = 0x100000

    TCI/DCI must not exceed 1MiB

Return values of MobiCore driver functions

.. data:: mcclient.OK = 0x00000000
.. data:: mcclient.NO_NOTIFICATION = 0x00000001
.. data:: mcclient.ERR_NOTIFICATION = 0x00000002
.. data:: mcclient.ERR_NOT_IMPLEMENTED = 0x00000003
.. data:: mcclient.ERR_OUT_OF_RESOURCES = 0x00000004
.. data:: mcclient.ERR_INIT = 0x00000005
.. data:: mcclient.ERR_UNKNOWN = 0x00000006
.. data:: mcclient.ERR_UNKNOWN_DEVICE = 0x00000007
.. data:: mcclient.ERR_UNKNOWN_SESSION = 0x00000008
.. data:: mcclient.ERR_INVALID_OPERATION = 0x00000009
.. data:: mcclient.ERR_INVALID_RESPONSE = 0x0000000a
.. data:: mcclient.ERR_TIMEOUT = 0x0000000b
.. data:: mcclient.ERR_NO_FREE_MEMORY = 0x0000000c
.. data:: mcclient.ERR_FREE_MEMORY_FAILED = 0x0000000d
.. data:: mcclient.ERR_SESSION_PENDING = 0x0000000e
.. data:: mcclient.ERR_DAEMON_UNREACHABLE = 0x0000000f
.. data:: mcclient.ERR_INVALID_DEVICE_FILE = 0x00000010
.. data:: mcclient.ERR_INVALID_PARAMETER = 0x00000011
.. data:: mcclient.ERR_KERNEL_MODULE = 0x00000012
.. data:: mcclient.ERR_BULK_MAPPING = 0x00000013
.. data:: mcclient.ERR_BULK_UNMAPPING = 0x00000014
.. data:: mcclient.INFO_NOTIFICATION = 0x00000015
.. data:: mcclient.ERR_NQ_FAILED = 0x00000016
.. data:: mcclient.ERR_DAEMON_VERSION = 0x00000017
.. data:: mcclient.ERR_CONTAINER_VERSION = 0x00000018
.. data:: mcclient.ERR_WRONG_PUBLIC_KEY = 0x00000019
.. data:: mcclient.ERR_CONTAINER_TYPE_MISMATCH = 0x0000001a
.. data:: mcclient.ERR_CONTAINER_LOCKED = 0x0000001b
.. data:: mcclient.ERR_SP_NO_CHILD = 0x0000001c
.. data:: mcclient.ERR_TL_NO_CHILD = 0x0000001d
.. data:: mcclient.ERR_UNWRAP_ROOT_FAILED = 0x0000001e
.. data:: mcclient.ERR_UNWRAP_SP_FAILED = 0x0000001f
.. data:: mcclient.ERR_UNWRAP_TRUSTLET_FAILED = 0x00000020
.. data:: mcclient.ERR_DAEMON_DEVICE_NOT_OPEN = 0x00000021
.. data:: mcclient.ERR_TA_HEADER_ERROR = 0x00000021
.. data:: mcclient.ERR_TA_ATTESTATION_ERROR = 0x00000022
.. data:: mcclient.ERR_INTERRUPTED_BY_SIGNAL = 0x00000023
.. data:: mcclient.ERR_SERVICE_BLOCKED = 0x00000024
.. data:: mcclient.ERR_SERVICE_LOCKED = 0x00000025
.. data:: mcclient.ERR_SERVICE_KILLED = 0x00000026
.. data:: mcclient.ERR_NO_FREE_INSTANCES = 0x00000027

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

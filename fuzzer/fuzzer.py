import argparse
import collections
import os
import signal
import struct
import sys

from unicorn import *
from unicorn.arm_const import *


MCLF_STRUCT = struct.Struct("IIIIII16sIIIIIIII")
MCLF_TUPLE = collections.namedtuple('MCLF',
    ['magic', 'version', 'flags', 'mem_type', 'service_type',
     'num_instances', 'uuid', 'driver_id', 'num_threads', 'text_va',
     'text_len', 'data_va', 'data_len', 'bss_len', 'entry'])


class Emulator(object):
    ALIGN_PAGE = staticmethod(lambda x: x & ~(Emulator.page_size - 1))
    ROUND_PAGE = staticmethod(lambda x: Emulator.ALIGN_PAGE(x + Emulator.page_size))

    page_size = 0x1000
    memory_pages = []

    tl_api_lib_entry = 0x108c
    tl_api_lib_addr = 0x07d00000
    tci_buffer_addr = 0x100000

    def __init__(self, args):
        self.args = args
        self.parse_binary()
        self.check_binary()

        # Initialize the engine
        mode = UC_MODE_THUMB if self.mclf.entry & 1 else UC_MODE_ARM
        self.uc = Uc(UC_ARCH_ARM, mode)

        self.map_sections()
        self.map_shared_memory()
        self.map_tlapi_handler()

        # Add the debug hook if needed
        if args.debug:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
            self.cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            self.cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            self.uc.hook_add(UC_HOOK_CODE, self.DEBUG)

        self.start_forkserver()
        self.load_input()

        try:
            self.LOG("[+] Starting fuzzing")
            self.uc.emu_start(self.mclf.entry | 1,
                              self.mclf.text_va +
                              self.mclf.text_len,
                              count=0,
                              timeout=0)
        except UcError as e:
            self.force_crash(e)

    def start_forkserver(self):
        self.LOG("Starting the AFL forkserver by executing 1 instruction")
        try:
            self.uc.emu_start(self.mclf.entry | 1, 0, 0, count=1)
        except UcError as e:
            self.LOG("Failed to execute a single instruction: %s" % e)

    def load_input(self):
        self.LOG("Loading data input from %s" % self.args.input)
        with open(self.args.input, 'rb') as f:
            input = f.read()
            if len(input) > self.args.tci:
                self.LOG("Test input is too long")
            else:
                self.write_mem(self.tci_buffer_addr, input)

    def force_crash(self, uc_error):
        mem_errors = [
            UC_ERR_READ_UNMAPPED, UC_ERR_READ_PROT, UC_ERR_READ_UNALIGNED,
            UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED,
            UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNALIGNED,
        ]
        if uc_error.errno in mem_errors:
            os.kill(os.getpid(), signal.SIGSEGV)
        elif uc_error.errno == UC_ERR_INSN_INVALID:
            os.kill(os.getpid(), signal.SIGILL)
        else:
            os.kill(os.getpid(), signal.SIGABRT)

    def parse_binary(self):
        # Read the trustlet binary
        with open(self.args.binary, "rb") as f:
            self.mclf = MCLF_TUPLE(*MCLF_STRUCT.unpack(f.read(72)))
            f.seek(0)
            self.code = f.read(self.mclf.text_len)
            f.seek(self.mclf.text_len)
            self.data = f.read(self.mclf.data_len)

    def check_binary(self):
        # Check the service type
        if self.mclf.service_type in [2, 3]:
            self.LOG("[+] Binary is a trustlet")
        else:
            raise Exception("[!] Unsupported binary")

        # Print basic information
        self.LOG("[+] Trustlet size = 0x{:x}"
                 .format(self.mclf.text_len +
                         self.mclf.data_len +
                         self.mclf.bss_len))

    def map_sections(self):
        # Map the text section
        self.LOG("[+] Mapping text section at 0x{:08x} with a size of 0x{:x}"
                 .format(self.mclf.text_va, self.mclf.text_len))
        self.map_mem(self.mclf.text_va, self.mclf.text_len)
        self.write_mem(self.mclf.text_va, self.code)

        # Map the data section
        self.LOG("[+] Mapping data section at 0x{:08x} with a size of 0x{:x}"
                 .format(self.mclf.data_va, self.mclf.data_len))
        self.map_mem(self.mclf.data_va, self.mclf.data_len)
        self.write_mem(self.mclf.data_va, self.data)

        # Map the BSS section
        bss_va = self.mclf.data_va + self.mclf.data_len
        self.LOG("[+] Mapping BSS section at 0x{:08x} with a size of 0x{:x}"
                 .format(bss_va, self.mclf.bss_len))
        self.map_mem(bss_va, self.mclf.bss_len)
        self.write_mem(bss_va, b'\x00' * self.mclf.bss_len)

    def map_shared_memory(self):
        # Map the TCI buffer
        self.LOG("[+] Mapping TCI buffer at 0x{:08x} with a size of 0x{:x}"
                 .format(self.tci_buffer_addr, self.args.tci))
        self.map_mem(self.tci_buffer_addr, self.args.tci)

        # Write the TCI buffer address and length
        end_of_bss = self.mclf.data_va + self.mclf.data_len + self.mclf.bss_len
        self.write_dword(end_of_bss - 8, self.tci_buffer_addr)
        self.write_dword(end_of_bss - 4, self.args.tci)

    def map_tlapi_handler(self):
        # Map the tlApi handler
        self.map_mem(self.tl_api_lib_addr, 1)
        self.write_dword(self.tl_api_lib_entry, self.tl_api_lib_addr)

        # Hook the tlApi handler
        self.uc.hook_add(UC_HOOK_CODE, self.handle_tl_api,
                         begin=self.tl_api_lib_addr,
                         end=self.tl_api_lib_addr + 1)

    def handle_tl_api(self, uc, address, size, user_data):
        tl_api_func_id = self.read_reg(UC_ARM_REG_R0)
        self.LOG("[+] Calling tlApi with ID 0x{:x}".format(tl_api_func_id))

        if tl_api_func_id == 0x4:
            self.handle_tl_api_exit("tlApiExit")
        elif tl_api_func_id == 0x6:
            pass  # tlApiWaitNotification
        elif tl_api_func_id == 0x7:
            self.handle_tl_api_exit("tlApiNotify")
        else:
            self.set_ret(0)
        self.force_ret()

    def handle_tl_api_exit(self, caller):
        self.LOG("[+] {}: Quitting!".format(caller))
        self.uc.emu_stop()
        sys.exit(0)

    def LOG(self, msg):
        print(msg)

    def DEBUG(self, uc, address, size, user_data):
        pc = self.read_reg(UC_ARM_REG_PC)
        try:
            ins = bytes(self.uc.mem_read(pc, 4))
            if self.uc.query(UC_QUERY_MODE) == UC_MODE_ARM:
                cs = self.cs_arm
            elif self.uc.query(UC_QUERY_MODE) == UC_MODE_THUMB:
                cs = self.cs_thumb
            _, __, mnem, op_str = next(cs.disasm_lite(ins, 4))
            ins_disas = '{} {}'.format(mnem, op_str)
        except:
            ins_disas = 'ERROR'
        self.LOG('[+] {:08x}:\t{}'.format(pc, ins_disas.upper()))

    def read_reg(self, reg):
        return self.uc.reg_read(reg)

    def write_reg(self, reg, value):
        return self.uc.reg_write(reg, value)

    def set_ret(self, val):
        self.write_reg(UC_ARM_REG_R0, val)

    def force_ret(self):
        self.write_reg(UC_ARM_REG_PC, self.read_reg(UC_ARM_REG_LR))

    def read_mem(self, addr, sz):
        return self.uc.mem_read(addr, sz)

    def read_byte(self, addr):
        return struct.unpack("<B", self.read_mem(addr, 1))[0]

    def read_word(self, addr):
        return struct.unpack("<H", self.read_mem(addr, 2))[0]

    def read_dword(self, addr):
        return struct.unpack("<I", self.read_mem(addr, 4))[0]

    def read_qword(self, addr):
        return struct.unpack("<Q", self.read_mem(addr, 8))[0]

    def write_mem(self, addr, data):
        return self.uc.mem_write(addr, data)

    def write_byte(self, addr, val):
        return self.write_mem(addr, struct.pack("<B", val))

    def write_word(self, addr, val):
        return self.write_mem(addr, struct.pack("<H", val))

    def write_dword(self, addr, val):
        return self.write_mem(addr, struct.pack("<I", val))

    def write_qword(self, addr, val):
        return self.write_mem(addr, struct.pack("<Q", val))

    def map_mem(self, addr, size):
        self.LOG("[+] Mapping region at 0x{:08x} (0x{:x} bytes)"
                 .format(addr, size))
        maddr = self.ALIGN_PAGE(addr)
        msize = self.ROUND_PAGE(addr - maddr + size)
        pages = []

        for page_addr in range(maddr, maddr + msize, self.page_size):
            if page_addr not in self.memory_pages:
                if pages and pages[-1][0] + pages[-1][1] == page_addr:
                    pages[-1] = pages[-1][0], pages[-1][1] + self.page_size
                else:
                    pages.append((page_addr, self.page_size))
                self.memory_pages.append(page_addr)

        for page_addr, page_size in pages:
            self.uc.mem_map(page_addr, page_size)


if __name__ == "__main__":
    def sigint_handler(_, __):
        exit()
    signal.signal(signal.SIGINT, sigint_handler)

    parser = argparse.ArgumentParser(description='Trustlets emulator')
    parser.add_argument('binary', type=str, help='binary path')
    parser.add_argument('input', type=str, help='input file')
    parser.add_argument('--tci', '-t', type=int, metavar='buffer_size',
                        default=Emulator.page_size, help="tci buffer size")
    parser.add_argument('--debug', '-d', action='store_true',
                        help='enable debug logs')
    Emulator(parser.parse_args())

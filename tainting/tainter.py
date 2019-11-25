#!/usr/bin/env python3
import argparse
import os
import struct

from manticore import Manticore, issymbolic
from manticore.core.state import TerminateState

import capstone as cs


def main(args):
    m = Manticore(args.binary, ['anything'])
    m.verbosity(args.verbosity)

    taint_id = 'user_ctrl'
    modules = []
    blocks = set()

    tl_api_lib_entry = 0x7d00000
    tl_api_lib_entry_ptr = 0x108c

    tci_buffer_addr = 0x100000
    tci_buffer_size = args.size

    @m.init
    def setup(state):
        elf = state.platform.elf

        text = elf.get_segment(0)
        text_addr = text['p_vaddr']
        text_size = text['p_memsz']
        name = os.path.basename(args.binary)
        modules.append((0, text_addr + text_size, name))

        data = elf.get_segment(1)
        data_addr = data['p_vaddr']
        data_size = data['p_memsz']

        shrmem_ptr_addr = data_addr + data_size - 8
        shrmem_ptr_size = data_addr + data_size - 4

        for start, end, _, _, _ in state.cpu.memory.mappings():
            if start > data_addr + data_size:
                state.cpu.memory.munmap(start, end - start)

        state.cpu.memory.mmap(tci_buffer_addr, tci_buffer_size, 'rw')
        state.cpu.write_bytes(tci_buffer_addr, '\x00' * tci_buffer_size)

        state.cpu.write_bytes(shrmem_ptr_addr,
                              struct.pack('<I', tci_buffer_addr))
        state.cpu.write_bytes(shrmem_ptr_size,
                              struct.pack('<I', tci_buffer_size))

        tl_api_code = b'\x4f\xf0\x00\x00'   # mov.w r0, #0
        tl_api_code += b'\x70\x47'          # bx lr
        state.cpu.memory.mmap(tl_api_lib_entry, len(tl_api_code), 'rw')
        state.cpu.write_bytes(tl_api_lib_entry, tl_api_code)
        state.cpu.memory.mprotect(tl_api_lib_entry, len(tl_api_code), 'rx')

        state.cpu.write_bytes(tl_api_lib_entry_ptr,
                              struct.pack('<I', tl_api_lib_entry | 1),
                              force=True)

    @m.hook(tl_api_lib_entry)
    def tl_api(state):
        tl_api_func_id = state.cpu.read_register('R0')

        if tl_api_func_id == 0x6:
            print("Calling tlApiWaitNotification")
            tci_buffer = state.new_symbolic_buffer(tci_buffer_size,
                                                   taint=(taint_id,))
            state.cpu.write_bytes(tci_buffer_addr, tci_buffer)

        elif tl_api_func_id == 0x7:
            print("Calling tlApiNotify")
            raise TerminateState('tlApiNotify', testcase=False)

        elif tl_api_func_id == 0x4:
            print("Calling tlApiExit")
            raise TerminateState('tlApiExit', testcase=False)

        else:
            print("Calling unknown tlApi %#x" % tl_api_func_id)

    def has_tainted_operands(operands):
        for operand in operands:
            op = operand.read()
            if issymbolic(op) and taint_id in op.taint:
                return True
        return False

    def has_tainted_flags(state, cc):
        if cc == cs.arm.ARM_CC_AL:
            ret = []
        elif cc == cs.arm.ARM_CC_EQ:
            ret = ['Z']
        elif cc == cs.arm.ARM_CC_NE:
            ret = ['Z']
        elif cc == cs.arm.ARM_CC_HS:
            ret = ['C']
        elif cc == cs.arm.ARM_CC_LO:
            ret = ['C']
        elif cc == cs.arm.ARM_CC_MI:
            ret = ['N']
        elif cc == cs.arm.ARM_CC_PL:
            ret = ['N']
        elif cc == cs.arm.ARM_CC_VS:
            ret = ['V']
        elif cc == cs.arm.ARM_CC_VC:
            ret = ['V']
        elif cc == cs.arm.ARM_CC_HI:
            ret = ['C', 'Z']
        elif cc == cs.arm.ARM_CC_LS:
            ret = ['C', 'Z']
        elif cc == cs.arm.ARM_CC_GE:
            ret = ['N', 'V']
        elif cc == cs.arm.ARM_CC_LT:
            ret = ['N', 'V']
        elif cc == cs.arm.ARM_CC_GT:
            ret = ['Z', 'N', 'V']
        elif cc == cs.arm.ARM_CC_LE:
            ret = ['Z', 'N', 'V']

        for flag in ret:
            flag_name = 'APSR_{}'.format(flag)
            flag_val = state.cpu.regfile.read(flag_name)
            if issymbolic(flag_val) and taint_id in flag_val.taint:
                return True
        return False

    @m.hook(None)
    def tainting_and_coverage(state):
        insn = state.cpu.instruction
        if args.tainting:
            if has_tainted_operands(insn.operands) \
                    or has_tainted_flags(state, insn.cc):
                print('Found tainted instruction:')
                print('    %#x: %s %s'
                      % (insn.address, insn.mnemonic, insn.op_str))
        if args.coverage:
            blocks.add((insn.address, insn.size))

    m.run()

    def write_coverage(f):
        f.write(b"DRCOV VERSION: 2\n")
        f.write(b"DRCOV FLAVOR: drcov\n")
        f.write(b"Module Table: version 2, count %u\n" % len(modules))
        f.write(b"Columns: id, base, end, entry, checksum, timestamp, path\n")

        fmt = b"%2u, 0x%x, 0x%x, 0x0000000000000000, "
        fmt += b"0x00000000, 0x00000000, %s\n"
        for mid, (base, end, path) in enumerate(modules):
            f.write(fmt % (mid, base, end, str.encode(path)))

        f.write(b"BB Table: %u bbs\n" % len(blocks))
        for addr, size in blocks:
            for mid, module in enumerate(modules):
                if addr >= module[0] and addr < module[1]:
                    bb = struct.pack("<IHH", addr - module[0], size, mid)
                    f.write(bb)
                    break

    if args.coverage:
        with open(args.coverage, 'wb') as f:
            write_coverage(f)

    print('See {} for results.'.format(m.workspace))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Trustlets fuzzer')
    parser.add_argument('binary', metavar='BINARY', type=str,
                        help='binary path')
    parser.add_argument('--size', '-s', type=int, required=True,
                        help="tci buffer size")
    parser.add_argument('--tainting', '-t', action='store_true',
                        help='enable tainting')
    parser.add_argument('--coverage', '-c', type=str,
                        help='create coverage file')
    parser.add_argument('-v', '--verbosity', type=int, default=0,
                        choices=[0, 1, 2, 3, 4, 5],
                        help="increase output verbosity")
    main(parser.parse_args())

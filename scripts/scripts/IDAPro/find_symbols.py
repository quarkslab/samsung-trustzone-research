import inspect
import json
import os
import sys

import ida_allins
import ida_bytes
import ida_funcs
import ida_gdl
import ida_idaapi
import ida_idp
import ida_name
import ida_segment
import ida_typeinf
import ida_ua
import ida_xref

TL_APIS = {}
MAX_TL_API = 0xC2

DR_APIS = {}
MAX_DR_API = 0x3D


if sys.version_info[0] < 3:
    def encode(s):
        return s.encode("utf-8")
else:
    def encode(s):
        return s

def define_missed_functions():
    def match(F):
        return ida_bytes.is_code(F) and not ida_bytes.is_flow(F)

    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if seg.type != ida_segment.SEG_CODE:
            continue
        print("[*] Browsing segment from %#x for %#x" % (seg.start_ea, seg.end_ea))

        ea = seg.start_ea
        while ea < seg.end_ea:
            ea = ida_bytes.next_that(ea, seg.end_ea, match)
            if ea == ida_idaapi.BADADDR:
                break
            if ida_funcs.get_func(ea):
                continue
            s = "[*] Trying to define function at %#x... " % ea
            if not ida_funcs.add_func(ea):
                print(s + " Failed!")
            else:
                print(s + " Success!")


def load_api_names_types():
    curdir = os.path.dirname(os.path.abspath(inspect.getsourcefile(lambda: 0)))

    with open(os.path.join(curdir, 'tl_apis.json'), 'r') as f:
        TL_APIS.update({i: (n, t) for i, n, t in json.loads(f.read())})
    print("[*] Loaded %s trustlets APIs names" % len(TL_APIS))

    global DR_APIS
    with open(os.path.join(curdir, 'dr_apis.json'), 'r') as f:
        DR_APIS.update({i: (n, t) for i, n, t in json.loads(f.read())})
    print("[*] Loaded %s drivers APIs names" % len(DR_APIS))


def get_api_name_type(api_number):
    if api_number in TL_APIS:
        return TL_APIS[api_number]

    if api_number - 0x1000 in DR_APIS:
        return DR_APIS[api_number - 0x1000]

    if 0 <= api_number < MAX_TL_API:
        return 'tlApi_%04x' % api_number, None

    if 0 <= api_number - 0x1000 < MAX_DR_API:
        return 'drApi_%04x' % api_number, None

    return None, None


def xrefs_to_lib_entry():
    tl_api_lib_entry = ida_name.get_name_ea(ida_idaapi.BADADDR,
                                            'tlApiLibEntry')
    if tl_api_lib_entry == ida_idaapi.BADADDR:
        return

    xref = ida_xref.xrefblk_t()
    xref.first_to(tl_api_lib_entry, ida_xref.XREF_DATA)
    while True:
        yield xref.frm
        if not xref.next_to():
            break


def find_chunk_boundaries(ea):
    def match(F):
        return ida_bytes.is_code(F) and not ida_bytes.is_flow(F)

    chunk_end = ida_bytes.next_that(ea + 1, ida_idaapi.BADADDR, match)
    return ida_bytes.prev_that(ea, 0, match), chunk_end


def determine_api_number(ea, chunk_start, chunk_end):
    def get_reg_num(reg_name):
        reg_inf = ida_idp.reg_info_t()
        ida_idp.parse_reg_name(reg_inf, reg_name)
        return reg_inf.reg

    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, ea)
    if insn.itype != ida_allins.ARM_ldr \
            or insn.ops[0].type != ida_ua.o_reg:
        reg = -1
    else:
        reg = insn.ops[0].reg

    reg_val = -1
    ins_ea = chunk_start
    while ins_ea < chunk_end:
        insn = ida_ua.insn_t()
        ins_len = max(1, ida_ua.decode_insn(insn, ins_ea))

        if insn.itype == ida_allins.ARM_mov \
                and insn.ops[0].type == ida_ua.o_reg \
                and insn.ops[0].reg == get_reg_num('R0') \
                and insn.ops[1].type == ida_ua.o_imm:
            reg_val = insn.ops[1].value

        if insn.itype == ida_allins.ARM_bx \
                and insn.ops[0].type == ida_ua.o_reg \
                and (insn.ops[0].reg == reg or reg == -1):
            break
        ins_ea += ins_len
    return reg_val


def has_only_one_basic_block(func):
    if func is None:
        return False
    return ida_gdl.FlowChart(func).size == 1


def set_function_prototype(func, proto):
    t = ida_typeinf.idc_parse_decl(None, proto, 0)
    ida_typeinf.apply_type(None, t[1], t[2], func.start_ea,
                           ida_typeinf.TINFO_DEFINITE)


load_api_names_types()
define_missed_functions()

for ea in xrefs_to_lib_entry():
    chunk_start, chunk_end = find_chunk_boundaries(ea)
    if chunk_start == ida_idaapi.BADADDR or chunk_end == ida_idaapi.BADADDR:
        print("[!] %#x - Couldn't find chunk boudaries" % ea)
        continue

    api_number = determine_api_number(ea, chunk_start, chunk_end)
    if api_number == -1:
        print("[!] %#x - Couldn't determine the api number" % ea)
        continue

    api_name, api_type = get_api_name_type(api_number)
    if api_name is None:
        print("[!] %#x - Couldn't get the api name" % ea)
        continue

    func = ida_funcs.get_func(ea)
    if not has_only_one_basic_block(func):
        print("[!] %#x - Function has more than one basic block" % ea)
        continue

    func_name = ida_name.get_name(func.start_ea)
    print("[*] Renaming function %s to %s" % (func_name, api_name))
    ida_name.set_name(func.start_ea, encode(api_name),
                      ida_name.SN_FORCE)

    if not api_type:
        continue
    print("[*] Changing function type of %s to '%s'" % (api_name, api_type))
    set_function_prototype(func, encode(api_type))

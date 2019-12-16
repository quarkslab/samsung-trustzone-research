import ida_allins
import ida_bytes
import ida_funcs
import ida_gdl
import ida_idp
import ida_name
import ida_segment
import ida_typeinf
import ida_ua

import inspect
import json
import os
import sys

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


def load_api_names_types():
    """
    Loads api function names and api function types from external json files
    and fills globals dict variables with these informations
    """
    curdir = os.path.dirname(os.path.abspath(inspect.getsourcefile(lambda: 0)))

    with open(os.path.join(curdir, "tl_apis.json"), "r") as f:
        TL_APIS.update({i: (n, t) for i, n, t in json.loads(f.read())})
    print("[*] Loaded %s trustlets APIs names" % len(TL_APIS))

    global DR_APIS
    with open(os.path.join(curdir, "dr_apis.json"), "r") as f:
        DR_APIS.update({i: (n, t) for i, n, t in json.loads(f.read())})
    print("[*] Loaded %s drivers APIs names" % len(DR_APIS))


def get_apis_name_type(api_number):
    """Retrieves API names and types from global

    :param api_number: API number
    :type api_number: int
    :return: TL API name, TL API type (possibly None), DR API name,
             DR API type (possibly None)
    :rtype: (str, str, str, str)
    """
    tl_api_name = None
    tl_api_type = None
    dr_api_name = None
    dr_api_type = None

    if api_number in TL_APIS:
        tl_api_name, tl_api_type = TL_APIS[api_number]

    if api_number in DR_APIS:
        dr_api_name, dr_api_type = DR_APIS[api_number]

    if tl_api_name is None:
        if 0 <= api_number < MAX_TL_API:
            tl_api_name = "tlApi_%x" % api_number

    if dr_api_name is None:
        if 0 <= api_number < MAX_DR_API:
            dr_api_name = "drApi_%x" % api_number

    return tl_api_name, tl_api_type, dr_api_name, dr_api_type


def get_reg_num(reg_name):
    """Retrieves the reg_inf.reg (register number) of a given register name

    :param reg_name: Register name
    :type reg_name: str
    :return: Register number
    :rtype: int
    """
    reg_inf = ida_idp.reg_info_t
    reg_inf = ida_idp.reg_info_t()
    ida_idp.parse_reg_name(reg_inf, reg_name)
    return reg_inf.reg


def find_mclib_jumper():
    """Retrieves the address of the McLib jumper fills by the loader during
    the trustlet loading process

    :return: McLib jumper address
    :rtype: int
    """
    segm = ida_segment.get_segm_by_name("rtm")
    mclib_jumper = ida_bytes.get_dword(segm.start_ea + 0x8C)

    return mclib_jumper


def get_handler(mclib_jumper):
    """Retrieves the handler of the TL/DR API calls

    :param mclib_jumper: Address of the McLib jumper
    :type mclib_jumper: int
    :return: Handler of the TL/DR API calls
    :rtype: int
    """
    handler = -1
    insn = ida_ua.insn_t()

    ida_ua.decode_insn(insn, mclib_jumper)
    if insn.itype == ida_allins.ARM_adr and \
            insn.ops[0].type == ida_ua.o_reg and \
            insn.ops[0].reg == get_reg_num("PC") and \
            insn.ops[1].type == ida_ua.o_imm:
        handler = insn.ops[1].value
    return handler


def get_dispatcher(handler):
    """Retrieves the dispatcher of the TL/DR API calls

    :param handler: Handler of the TL/DR API calls
    :type handler: int
    :return: Dispatcher for the TL/DR API calls
    :rtype: int
    """

    func = ida_funcs.get_func(handler)
    insn = ida_ua.insn_t()
    ea = 0
    branch_addr = -1

    ea = func.start_ea

    while ea < func.end_ea:
        insn = ida_ua.insn_t()
        insn_len = max(1, ida_ua.decode_insn(insn, ea))
        if insn.itype == ida_allins.ARM_bl and \
                insn.ops[0].type == ida_ua.o_near:
            branch_addr = insn.ops[0].addr
            break
        ea += insn_len

    return branch_addr


def get_tl_dr_api_table(dispatcher):
    """Retrieves function tables for TL/DR API calls

    :param dispatcher: Dispatcher of the TL/DR calls
    :type dispatcher: int
    :return: Driver API function table and Trustlet API function table
    :rtype: (int, int)
    """

    def get_cmp(func_start, func_end):
        """Retrives the address of the CMP within the dispatching function

        :param func_start: Beginning of the dispatching function
        :type func_start: int
        :param func_end: Ending of the dispatching function
        :type func_end: int
        :return: Address of the CMP within the dispatching function
        :rtype: int
        """

        cmp_addr = -1
        insn_ea = func_start
        insn = ida_ua.insn_t()
        insn_len = 0

        while insn_ea < func_end:
            insn_len = max(1, ida_ua.decode_insn(insn, insn_ea))
            if insn.itype == ida_allins.ARM_cmp and \
                    insn.ops[1].type == ida_ua.o_imm and \
                    insn.ops[1].value == 0x1000:
                cmp_addr = insn_ea
                break
            insn_ea += insn_len
        return cmp_addr

    def find_dr_tl_addr(blocks_info):
        """Retrieves the address of the tables defining the DR/TL API calls

        :param blocks_info: List of tuples defining the current blocks to process. Each tuple is defined with the form (BasicBlock, bool), where bool defines if the Basic Block belongs to a branch dealing with the driver case.
        :type blocks_info: list(tuple(ida_gdl.BasicBlock, bool))
        :return: The address of the DrApi and TlApi tables
        :rtype: (int, int)
        """

        tl_table = -1
        dr_table = -1
        new_blocks = []
        is_dr_branch = False
        is_dr_block = False

        def analyze_block(block):
            """Analyze a basic bloc and return its successors, if it's correspond to a basic bloc treating the Driver case and the address for the DR/TL API table if one is loaded

            :param block: Basic block to analyze
            :type block: ida_gdl.BasicBlock
            :return: Successors Basic Blocks, if it deals with Secure Driver case, and the address of the table loaded if loaded
            :rtype: (Generator, bool, int)
            """

            loaded_value = -1
            is_dr_table = False
            insn = ida_ua.insn_t()
            insn_ea = block.start_ea
            insn_len = 0

            while insn_ea < block.end_ea:
                insn_len = max(1, ida_ua.decode_insn(insn, insn_ea))
                if insn.itype == ida_allins.ARM_sub and \
                        insn.ops[2].type == ida_ua.o_imm and \
                        insn.ops[2].value == 0x1000:
                    is_dr_table = True
                if insn.itype == ida_allins.ARM_ldr and \
                        insn.ops[1].type == ida_ua.o_mem:
                    pool_value = ida_bytes.get_dword(insn.ops[1].addr)
                    value = ida_bytes.get_dword(pool_value)
                    if value > 0x1000:
                        loaded_value = pool_value
                insn_ea += insn_len
            return block.succs(), is_dr_table, loaded_value

        # Walk through every Basic Block of the function using the previously defined function until we find the value of the DR/TL API tables
        while True:
            new_blocks = []

            for block, is_dr_branch in blocks_info:
                successors, is_dr_block, loaded_value = analyze_block(block)
                new_blocks += [(successor, is_dr_block) for successor in successors]
                if loaded_value != -1 and not is_dr_branch:
                    tl_table = loaded_value
                if loaded_value != -1 and is_dr_branch:
                    dr_table = loaded_value

            blocks_info = new_blocks
            if dr_table != -1 and tl_table != -1:
                return dr_table, tl_table

    func = ida_funcs.get_func(dispatcher)
    func_start, func_end = func.start_ea, func.end_ea

    # First, locate the CMP.W R1, 0x1000
    cmp_addr = -1
    cmp_addr = get_cmp(func_start, func_end)
    if cmp_addr == -1:
        print("[!] %#x - Couldn't find tl/dr api check" % dispatcher)

    # Second, get the basic blocks containing the table for drapi and tlapi
    fc = ida_gdl.FlowChart(func)
    for block in fc:
        if block.start_ea <= cmp_addr and block.end_ea >= cmp_addr:
            bb = block
            break

    # Third, locate the drApi and tlApi function tables
    dr_table, tl_table = find_dr_tl_addr([(bb, False)])
    return dr_table, tl_table


def set_function_prototype(func, proto):
    """Set the prototype of a given function with the given type

    :param func: Function where we will apply the prototype
    :type func: ida_funcs.func_t
    :param proto: prototype we will apply to the given function
    :type api_type: str
    """
    t = ida_typeinf.idc_parse_decl(None, proto, 0)
    ida_typeinf.apply_type(None, t[1], t[2], func.start_ea,
                           ida_typeinf.TINFO_DEFINITE)


def set_name_prototype_tl_dr_function(api_number):
    """Set the name and the prototype of the TL/DR API function associated with the given function number

    :param api_number: API function number
    :type api_number: int
    """
    global MAX_TL_API
    global MAX_DR_API

    tl_api_name, tl_api_type, dr_api_name, dr_api_type = get_apis_name_type(api_number)
    index = api_number * 4

    if api_number < MAX_TL_API:
        if not tl_api_name:
            pass
        else:
            dword = ida_bytes.get_dword(tl_table + index)
            func = ida_funcs.get_func(dword)
            if func is None:
                MAX_TL_API = dword
            else:
                func_name = ida_name.get_name(func.start_ea)
                print("[*] Renaming function %s to %s" % (func_name, tl_api_name))
                ida_name.set_name(func.start_ea, encode(tl_api_name), ida_name.SN_FORCE)
                if tl_api_type:
                    set_function_prototype(func, encode(tl_api_type))

    if api_number < MAX_DR_API:
        if not dr_api_name:
            pass
        else:
            dword = ida_bytes.get_dword(dr_table + index)
            func = ida_funcs.get_func(dword)
            if func is None:
                MAX_DR_API = dword
            else:
                func_name = ida_name.get_name(func.start_ea)
                print("[*] Renaming function %s to %s" % (func_name, tl_api_name))
                ida_name.set_name(func.start_ea, encode(dr_api_name), ida_name.SN_FORCE)
                if dr_api_type:
                    set_function_prototype(func, encode(dr_api_type))


load_api_names_types()
mclib_jumper = find_mclib_jumper()

handler = get_handler(mclib_jumper)
if handler == -1:
    print("[!] %#x - Couldn't get address of the tlApi/drApi handler" % mclib_jumper)

dispatcher = get_dispatcher(handler)
if dispatcher == -1:
    print("[!] %#x - Couldn't get address of the tlApi/drApi dispatcher" % handler)

dr_table, tl_table = get_tl_dr_api_table(dispatcher)
if not dr_table:
    print("[!] %#x - Couldn't find drApi table" % dispatcher)
if not tl_table:
    print("[!] %#x - Couldn't find tlApi table" % dispatcher)

for api_number in range(max(MAX_TL_API, MAX_DR_API)):
    set_name_prototype_tl_dr_function(api_number)

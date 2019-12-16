import inspect
import json
import os
import struct

from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import ReturnParameterImpl
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import SourceType
from java.util import ArrayList


TL_APIS = {}
MAX_TL_API = 0xC2

DR_APIS = {}
MAX_DR_API = 0x3D


blockModel = BasicBlockModel(currentProgram)
functionManager = currentProgram.getFunctionManager()
decompInterface = DecompInterface()
decompInterface.openProgram(currentProgram)
api = FlatProgramAPI(currentProgram, monitor)


def read_dword(address):
    dword = api.getBytes(address, 4)
    return struct.unpack('<I', dword)[0]


def load_api_names_types():
    """
    Loads api function names and api function types from external json files and fills globals dict variables with these informations
    """
    curdir = os.path.dirname(os.path.abspath(inspect.getsourcefile(lambda: 0)))

    with open(os.path.join(curdir, 'tl_apis.json'), 'r') as f:
        TL_APIS.update({i: (n, t) for i, n, t in json.loads(f.read())})
    print("[*] Loaded %s trustlets APIs names" % len(TL_APIS))

    global DR_APIS
    with open(os.path.join(curdir, 'dr_apis.json'), 'r') as f:
        DR_APIS.update({i: (n, t) for i, n, t in json.loads(f.read())})
    print("[*] Loaded %s drivers APIs names" % len(DR_APIS))


def get_apis_name_type(api_number):
    """Retrieves API names and types from global

    :param api_number: API number
    :type api_number: int
    :return: TL API name, TL API type (possibly None), DR API name, DR API type (possibly None)
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


def find_mclib_jumper():
    """Retrieves the address of the McLib jumper fills by the loader during the trustlet loading process

    :return: Address of the McLib jumper
    :rtype: Optional[ghidra.program.model.address.GenericAddress]
    """
    mclib_jumper = None
    mem_block = currentProgram.getMemory().getBlock("rtm")

    mclib_jumper = read_dword(mem_block.getStart().add(0x8C))
    mclib_jumper = api.toAddr(mclib_jumper) if mclib_jumper else None
    return mclib_jumper


def get_dispatcher(mclib_jumper):
    """Retrieves the dispatcher of the TL/DR API calls
    
    :param mclib_jumper: Handler of the TL/DR API calls
    :type mclib_jumper: ghidra.program.model.address.GenericAddress
    :return: Address of the dispatcher for the TL/DR API calls
    :rtype: Optional[ghidra.program.model.address.GenericAddress]

    """

    handler = None
    function = functionManager.getFunctionAt(mclib_jumper)
    if function is None:
        function = createFunction(mclib_jumper, None)

    decompileResults = decompInterface.decompileFunction(function, 30, monitor)
    hfunction = decompileResults.getHighFunction()
    ops = hfunction.getPcodeOps()
    while ops.hasNext() and not monitor.isCancelled():
        pcodeOpAST = ops.next()
        if pcodeOpAST.getOpcode() != PcodeOp.CALL:
            continue
        argument = pcodeOpAST.getInput(0)
        if argument.isAddress():
            handler = api.toAddr(argument.getAddress().getUnsignedOffset())
            return handler
    return handler


def get_tl_dr_api_table(dispatcher):
    """Retrieves function tables for TL/DR API calls

    :param dispatcher: Dispatcher of the TL/DR calls
    :type dispatcher: int
    :return: Driver API function table and Trustlet API function table
    :rtype: (int, int)
    """

    def get_table_addr_and_type(table_pcode_op_ast):
        """Retrives address and type of a given table

        :param table_pcode_op_ast: pcodeOpAST associated with the given table load instruction
        :type pcode_op_ast: ghidra.program.model.pcode.PcodeOpAST
        :return: Address and type of the given table
        :rtype: (int, Optional[bool])
        """
        memory_varnode = table_pcode_op_ast.getInput(0)
        if memory_varnode.isAddress():
            table = read_dword(memory_varnode.getAddress())
            basicBlock = table_pcode_op_ast.getParent()
            for pcodeop in basicBlock.getIterator():
                opcode = pcodeop.getOpcode()
                if opcode == PcodeOp.INT_SUB and \
                        pcodeop.getInput(1).isConstant and \
                        pcodeop.getInput(1).getOffset() == 0x1000:
                    return table, True
 
                elif opcode == PcodeOp.INT_AND and \
                        pcodeop.getInput(1).isConstant() and \
                        pcodeop.getInput(1).getOffset() == 0x7FFFFFFF:
                    return table, None
            return table, False

    dr_table, tl_table = None, None

    function = functionManager.getFunctionAt(dispatcher)
    if function is None:
        function = createFunction(mclib_jumper, None)

    # First forward slice the first argument of the function until we find the
    # address where the API number is used to get the function pointer and retrieve
    # the base varnode (register) where is stored the table pointer
    decompileResults = decompInterface.decompileFunction(function, 30, monitor)
    hfunction = decompileResults.getHighFunction()
    varnode = hfunction.getFunctionPrototype().getParam(0).getRepresentative()

    forward_slices = DecompilerUtils.getForwardSlice(varnode)
    for forward_slice in forward_slices:
        pcode_op_ast = forward_slice.getDef()
        if not pcode_op_ast:
            continue
        if pcode_op_ast.getOpcode() == PcodeOp.PTRADD:
            array_varnode = pcode_op_ast.getInput(0)
            break

    # Second, backward slice the varnode used to store the base of the function pointer
    # table to get the values
    backward_slices = DecompilerUtils.getBackwardSlice(array_varnode)
    for backward_slice in backward_slices:
        pcode_op_ast = backward_slice.getDef()
        if not pcode_op_ast:
            continue
        if pcode_op_ast.getOpcode() == PcodeOp.COPY:
            table, table_type = get_table_addr_and_type(pcode_op_ast)
            if table_type is not None and table_type:
                dr_table = table
            elif table_type is not None and not table_type:
                tl_table = table

    return dr_table, tl_table


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
            dword = read_dword(api.toAddr(tl_table + index))
            if dword < 0x1000:
                MAX_TL_API = dword
            else:
                if (dword & 1) == 1:
                    dword -= 1
                func_addr = api.toAddr(dword)
                function = functionManager.getFunctionContaining(func_addr)
                if function is None:
                    function = createFunction(func_addr, None)
                if function is None:
                    print("[!] Unable to get the function at the address 0x%x" % dword)
                print("[*] Renaming function %s to %s" % (function.getName(), tl_api_name))
                function.setName(tl_api_name, SourceType.USER_DEFINED)
                if tl_api_type:
                    tl_api_type = tl_api_type.replace('_DWORD', 'int')
                    print("[*] Changing function type of %s to '%s'" % (tl_api_name, tl_api_type))
                    funcDef = CParserUtils.parseSignature(None, currentProgram, tl_api_type)
                    returnValue = ReturnParameterImpl(funcDef.getReturnType(), currentProgram)
                    newParams = ArrayList()
                    for param in funcDef.getArguments():
                        newParams.add(ParameterImpl(param.getName(), param.getDataType(), currentProgram))
                    function.updateFunction(None, returnValue, newParams,
                        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.USER_DEFINED)

    if api_number < MAX_DR_API:
        if not dr_api_name:
            pass
        else:
            dword = read_dword(api.toAddr(dr_table + index))
            if dword < 0x1000:
                MAX_DR_API = dword
            else:
                if (dword & 1) == 1:
                    dword -= 1
                func_addr = api.toAddr(dword)
                function = functionManager.getFunctionContaining(func_addr)
                if function is None:
                    function = createFunction(func_addr, None)
                if function is None:
                    print("[!] Unable to get the function at the address 0x%x" % dword)
                print("[*] Renaming function %s to %s" % (function.getName(), dr_api_name))
                function.setName(dr_api_name, SourceType.USER_DEFINED)
                if dr_api_type:
                    dr_api_type = dr_api_type.replace('_DWORD', 'int')
                    print("[*] Changing function type of %s to '%s'" % (dr_api_name, dr_api_type))
                    funcDef = CParserUtils.parseSignature(None, currentProgram, dr_api_type)
                    returnValue = ReturnParameterImpl(funcDef.getReturnType(), currentProgram)
                    newParams = ArrayList()
                    for param in funcDef.getArguments():
                        newParams.add(ParameterImpl(param.getName(), param.getDataType(), currentProgram))
                    function.updateFunction(
                        None,
                        returnValue,
                        newParams,
                        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        True,
                        SourceType.USER_DEFINED
                    )


load_api_names_types()
mclib_jumper = find_mclib_jumper()

dispatcher = get_dispatcher(mclib_jumper)
if not dispatcher:
    print("[!] %#x - Couldn't get address of the tlApi/drApi dispatcher" % dispatcher)

dr_table, tl_table = get_tl_dr_api_table(dispatcher)

for api_number in range(max(MAX_TL_API, MAX_DR_API)):
    set_name_prototype_tl_dr_function(api_number)

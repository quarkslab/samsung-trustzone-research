import json
import os
import inspect

from java.util import ArrayList
from ghidra.program.model.symbol import RefType
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.address import AddressSetView
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.model.listing import ReturnParameterImpl
from ghidra.program.model.listing import ParameterImpl


TL_APIS = {}
MAX_TL_API = 0xC2

DR_APIS = {}
MAX_DR_API = 0x3D


blockModel = BasicBlockModel(currentProgram)
functionManager = currentProgram.getFunctionManager()
decompInterface = DecompInterface()
decompInterface.openProgram(currentProgram)


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
    symbolTable = currentProgram.getSymbolTable()
    entry = symbolTable.getSymbol("tlApiLibEntry")
    xrefs = entry.getReferences()
    for xref in xrefs:
        if xref.getReferenceType() == RefType.READ:
            yield xref.getFromAddress()


def find_chunk_boundaries(address):
    blocks = blockModel.getCodeBlocksContaining(address, monitor)
    block = blocks[0]
    for i in range(1, len(blocks)):
        block = block.union(blocks[i])
    return block


def determine_api_number(function, block):
    decompileResults = decompInterface.decompileFunction(function, 30, monitor)
    hfunction = decompileResults.getHighFunction()
    ops = hfunction.getPcodeOps()
    while ops.hasNext() and not monitor.isCancelled():
        pcodeOpAST = ops.next()
        if pcodeOpAST.getOpcode() != PcodeOp.CALLIND:
            continue
        pcodeBlock = pcodeOpAST.getParent()
        if pcodeBlock.getStart() < block.getMinAddress() \
                or pcodeBlock.getStop() > block.getMaxAddress():
            continue
        argument = pcodeOpAST.getInput(1)
        if argument.isConstant():
            return argument.getOffset()
    return None


def has_only_one_basic_block(function):
    blockModel = BasicBlockModel(currentProgram)
    blocks = blockModel.getCodeBlocksContaining(function.getBody(), monitor)

    count = 0
    while blocks.hasNext():
        blocks.next()
        count += 1
    return count == 1


load_api_names_types()
for address in xrefs_to_lib_entry():
    block = find_chunk_boundaries(address)
    if not block:
        print("[!] 0x%s - Couldn't find chunk boudaries" % address)
        continue
    function = functionManager.getFunctionContaining(address)
    api_number = determine_api_number(function, block)
    if not api_number:
        print("[!] 0x%s - Couldn't determine the api number" % address)
        continue
    api_name, api_type = get_api_name_type(api_number)
    if api_name is None:
        print("[!] 0x%s - Couldn't get the api name" % address)
        continue
    if not has_only_one_basic_block(function):
        print("[!] 0x%s - Function has more than one basic block" % address)
        continue

    func_name = function.getName()
    print("[*] Renaming function %s to %s" % (func_name, api_name))
    function.setName(api_name, SourceType.USER_DEFINED)
    if not api_type:
        continue

    api_type = api_type.replace('_DWORD', 'int')
    print("[*] Changing function type of %s to '%s'" % (api_name, api_type))
    funcDef = CParserUtils.parseSignature(None, currentProgram, api_type)
    returnValue = ReturnParameterImpl(funcDef.getReturnType(), currentProgram)
    newParams = ArrayList()
    for param in funcDef.getArguments():
        newParams.add(ParameterImpl(param.getName(), param.getDataType(), currentProgram))
    function.updateFunction(None, returnValue, newParams,
        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.USER_DEFINED)

"""
    搜索一个ASCII字符串是否在Memory中出现
    Ghidra version: 11.0

    **单例模式, 仅处理current program**
"""
from collections.abc import Iterable

try:
    from ghidra.ghidra_builtins import *
except:
    pass

from ghidra.program.model.mem import Memory, MemoryBlock
from ghidra.program.model.listing import Program, Function, Instruction
from ghidra.program.model.address import AddressSet, Address

from ghidra.program.model.symbol import Reference
from ghidra.program.util import SymbolicPropogator
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer

from ghidra.util.classfinder import ClassSearcher

from .ACceptedAutomation.ahocorasick import AhoCorasick


__SEARCH_STRING_CURRENT_PROGRAM: Program = getCurrentProgram()

__SEARCH_BLOCKS:list[MemoryBlock] = []
__search_cache:dict[bytes, Iterable[Reference]] = {}

__SYMBOL_PROPOGATOR:SymbolicPropogator = None
__CONSTANT_PROPOGATOR:ConstantPropagationAnalyzer = None

def __init():
    
    # 添加所有可读的MemoryBlock到搜索空间
    memory: Memory = __SEARCH_STRING_CURRENT_PROGRAM.getMemory()
    for memblock in memory.getBlocks():
        if memblock.isRead() and memblock.isInitialized():
            __SEARCH_BLOCKS.append(memblock)
    
    global __CONSTANT_PROPOGATOR, __SYMBOL_PROPOGATOR

    for a in ClassSearcher.getInstances(ConstantPropagationAnalyzer):
        if a.canAnalyze(__SEARCH_STRING_CURRENT_PROGRAM):
            __CONSTANT_PROPOGATOR = a
            break
    else:
        assert 0

    __SYMBOL_PROPOGATOR = SymbolicPropogator(__SEARCH_STRING_CURRENT_PROGRAM)
    __SYMBOL_PROPOGATOR.setParamRefCheck(True)
    
def searchBytesAC(words: Iterable[bytes]) -> list[tuple[bytes, Address]]:
    

    AC = AhoCorasick(words)
    res = []
    for memblock in __SEARCH_BLOCKS:
        memblock: MemoryBlock
        st, ed = memblock.getStart().getOffset(), memblock.getEnd().getOffset()+1
        r = AC.query((
            memblock.getByte(toAddr(off)) & 0xff for off in range(st, ed)
        ))
        res += [(bs, toAddr(st+off)) for bs, off in r]
    return res


def searchBytes(_bytes: bytes, _cache: bool=True) -> list[int]:
    """
        搜索bytes

        _bytes: 待搜索bytes
        _cache: 缓冲搜索结果

        return: list[<bytes起始地址>] 
    """
    cached = __search_cache.get(_bytes)
    if cached is not None:
        return tuple(cached)

    positions = set()
    for memblock in __SEARCH_BLOCKS:
        
        st, ed = memblock.getStart().getOffset(), memblock.getEnd().getOffset() + 1
        
        if ed - st < len(_bytes):
            continue
        
        q, q_start = [], st
        for _ in range(st, st+len(_bytes)):
           q.append(memblock.getByte(toAddr(_)) & 0xff)
        
        while True:
            
            if bytes(q) == _bytes:
                positions.add(q_start)

            if q_start + len(_bytes) >= ed:
                break

            q.pop(0)
            try:
                q.append(memblock.getByte(toAddr(q_start+len(_bytes))) & 0xff)
            except ValueError as ve:
                print(hex(q_start+len(_bytes)))
                assert False
            q_start += 1
    
    if _cache:
        __search_cache[_bytes] = tuple(positions)
    
    return tuple(positions)

def searchBytesReferences(_bytes: bytes) -> list[Reference]:
    """
        搜索bytes的所有引用

        _bytes: 待搜索bytes

        return: list[搜索到的引用]
    """

    string_positions = searchBytes(_bytes, True)

    references = []
    for p in string_positions:
        for r in getReferencesTo(toAddr(p)):
            references.append(r)

    return references

def searchASCIIStringReferences(string: str) -> list[Reference]:
    """
        将str进行ascii编码并搜索引用
    """
    return searchBytesReferences(string.encode('ascii'))

def searchUTF8StringReferences(string: str) -> list[Reference]:
    """
        将str进行utf-8编码并搜索引用
    """
    return searchBytesReferences(string.encode('utf-8'))

def searchUTF16StringReferences(string: str) -> list[Reference]:
    """
        将str进行utf-16编码并搜索引用
    """
    return searchBytesReferences(string.encode('utf-16'))

def searchParaming(string: str) -> list[tuple[Function, int]]:
    """
        搜索常量字符串作为函数参数的引用
        Ghidra PARAM Reference + 向后搜索第一个引用

        return: list[tuple[callee, callsite]]
    """
    
    def searchCall(start: int) -> tuple[Function, int] | None:
        """
            从某个地址开始寻找一条call指令
        """
        
        inst: Instruction = getInstructionAt(toAddr(start))
        if str(__SEARCH_STRING_CURRENT_PROGRAM.getLanguageID().getIdAsString()).startswith('MIPS'):
            """
                - 如果当前指令是被跳转指令延迟的:
                    - 如果同时是call类型, 则从上一条开始寻找(实际上会直接返回上一条指令call的函数)
                    - 否则这条指令作为被分支指令延迟的指令一定会被执行, 因此仍然从这条指令开始寻找
                - 如果不是, 则正常从这条开始找
            """
            inst = inst.getPrevious()
            if not inst.getFlowType().isCall():
                inst = inst.getNext()
            start = inst.getAddress().getOffset()

        while True:
            
            if inst.getFlowType().isCall():
                
                callee: Function = None

                if inst.getPcode()[-1].getMnemonic() == 'CALL':
                    callee = getFunctionAt(inst.getOpObjects(0)[0])
                elif inst.getPcode()[-1].getMnemonic() == 'CALLIND':
                    
                    addrset = AddressSet(
                        __SEARCH_STRING_CURRENT_PROGRAM, 
                        toAddr(start), inst.getAddress()
                    )
                    
                    __CONSTANT_PROPOGATOR.flowConstants(
                        __SEARCH_STRING_CURRENT_PROGRAM,
                        toAddr(start),
                        addrset,
                        __SYMBOL_PROPOGATOR,
                        getMonitor()
                    )

                    entry: int = __SYMBOL_PROPOGATOR.getRegisterValue(inst.getAddress(), inst.getOpObjects(0)[0]).getValue()
                    callee = getFunctionAt(toAddr(entry))

                if callee:
                    return (callee, inst.getAddress().getOffset())

            elif inst.getFlowType().isConditional():
                break
            
            inst = inst.getNext()
            if inst is None:
                break
        
        return None
    
    __res = {
        searchCall(r.getFromAddress().getOffset()) for r in \
            searchUTF8StringReferences(string) + searchUTF16StringReferences(string) + searchASCIIStringReferences(string)
    }
    
    return __res


__init()
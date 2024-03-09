"""
    搜索一个ASCII字符串是否在Memory中出现
    Ghidra version: 11.0
"""
from collections.abc import Iterable
from typing import Callable, Any

try:
    from ghidra.ghidra_builtins import getCurrentProgram, getMonitor
except:
    pass

from ghidra.program.model.mem import Memory, MemoryBlock
from ghidra.program.model.listing import Program, Function, Instruction
from ghidra.program.model.address import AddressSet, Address

from ghidra.program.model.symbol import Reference
from ghidra.program.util import SymbolicPropogator
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer

from ghidra.util.classfinder import ClassSearcher


from .AhoCorasick import AhoCorasick


__SEARCH_STRING_CURRENT_PROGRAM: Program = None

__SEARCH_BLOCKS:list[MemoryBlock] = []
__search_cache:dict[bytes, Iterable[Reference]] = {}

__SYMBOL_PROPOGATOR:SymbolicPropogator = None
__CONSTANT_PROPOGATOR:ConstantPropagationAnalyzer = None

"""
    flat API
"""
getFunctionAt = None
getReferencesTo = None
toRAMAddr = None

"""
    configure API
"""
def reinit(program=None):

    global __SEARCH_STRING_CURRENT_PROGRAM
    __SEARCH_STRING_CURRENT_PROGRAM = getCurrentProgram() if program is None else program
    
    # 添加所有可读的MemoryBlock到搜索空间
    memory: Memory = __SEARCH_STRING_CURRENT_PROGRAM.getMemory()
    for memblock in memory.getBlocks():
        if memblock.isRead() and memblock.isInitialized():
            __SEARCH_BLOCKS.append(memblock)

    # 设置常量传播分析器
    global __CONSTANT_PROPOGATOR, __SYMBOL_PROPOGATOR
    for a in ClassSearcher.getInstances(ConstantPropagationAnalyzer):
        if a.canAnalyze(__SEARCH_STRING_CURRENT_PROGRAM):
            __CONSTANT_PROPOGATOR = a
            break
    else:
        assert 0
    __SYMBOL_PROPOGATOR = SymbolicPropogator(__SEARCH_STRING_CURRENT_PROGRAM)
    __SYMBOL_PROPOGATOR.setParamRefCheck(True)
    
    # 加载program对应的flatapi
    global getReferencesTo, toRAMAddr, getFunctionAt
    toRAMAddr = __SEARCH_STRING_CURRENT_PROGRAM.getAddressFactory().getAddressSpace('ram').getAddress
    getReferencesTo = __SEARCH_STRING_CURRENT_PROGRAM.getReferenceManager().getReferencesTo
    getFunctionAt = __SEARCH_STRING_CURRENT_PROGRAM.getListing().getFunctionAt


"""
    internal API
"""

def __searchCall(start: int) -> tuple[Function, int] | None:
    """
        从某个地址开始寻找一条call指令
    """
    
    inst: Instruction = __SEARCH_STRING_CURRENT_PROGRAM.getListing().getInstructionAt(toRAMAddr(start))
    if inst is None:
        return None

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
                    toRAMAddr(start), inst.getAddress()
                )
                
                __CONSTANT_PROPOGATOR.flowConstants(
                    __SEARCH_STRING_CURRENT_PROGRAM,
                    toRAMAddr(start),
                    addrset,
                    __SYMBOL_PROPOGATOR,
                    getMonitor()
                )

                regval: int = __SYMBOL_PROPOGATOR.getRegisterValue(inst.getAddress(), inst.getOpObjects(0)[0])
                callee = getFunctionAt(toRAMAddr(regval.getValue())) if regval else None

            if callee:
                return (callee, inst.getAddress().getOffset())

        elif inst.getFlowType().isConditional():
            break
        
        inst = inst.getNext()
        if inst is None:
            break
    
    return None


"""
    multi matching in one memory traversal -- Aho-Corasick API
"""
def searchMultiBytesAC(strings: Iterable[bytes]) -> list[tuple[bytes, Address]]:
    """
        AC自动机

        TODO: 内存开销测试

        strings: 一些待匹配字节串
        return: list[(字节串, 起始地址)]
    """
    
    AC = AhoCorasick(strings)
    res = []
    for memblock in __SEARCH_BLOCKS:
        memblock: MemoryBlock
        st, ed = memblock.getStart().getOffset(), memblock.getEnd().getOffset()+1
        r = AC.query((
            memblock.getByte(toRAMAddr(off)) & 0xff for off in range(st, ed)
        ))
        res += [(bs, toRAMAddr(st+off)) for bs, off in r]
    return res

def searchMultiBytesReferences(strings: Iterable[bytes]) -> list[tuple[bytes, Reference]]:
    """
        搜索字节串的内存引用(getReferencesTo)

        strings: 一些待搜索字节串
        return: list[(字节串, 引用地址)] 
    """
    res = []
    for w, addr in searchMultiBytesAC(strings):
        for r in getReferencesTo(addr):
            res.append((w, r))
    return res

def searchMultiUTF8StringReferences(strings: Iterable[str]) -> list[tuple[str, Reference]]:
    """
        将字符串进行UTF-8编码并搜索内存引用, 见searchMultiBytesReferences
    """
    return [
        (w.decode('utf-8'), r) for w, r in searchMultiBytesReferences((_.encode('utf-8') for _ in strings))
    ]

def searchMultiUTF16StringReferences(strings: Iterable[str]) -> list[tuple[str, Reference]]:
    """
        将字符串进行UTF-16编码并搜索内存引用, 见searchMultiBytesReferences
    """
    return [
        (w.decode('utf-16'), r) for w, r in searchMultiBytesReferences((_.encode('utf-16') for _ in strings))
    ]


"""
    single string searching API
"""
def searchBytes(_bytes: bytes, _cache: bool=True) -> list[int]:
    """
        暴力搜索内存中指定字节串的起始地址

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
           q.append(memblock.getByte(toRAMAddr(_)) & 0xff)
        
        while True:
            
            if bytes(q) == _bytes:
                positions.add(q_start)

            if q_start + len(_bytes) >= ed:
                break

            q.pop(0)
            try:
                q.append(memblock.getByte(toRAMAddr(q_start+len(_bytes))) & 0xff)
            except ValueError as ve:
                print(hex(q_start+len(_bytes)))
                assert False
            q_start += 1
    
    if _cache:
        __search_cache[_bytes] = tuple(positions)
    
    return tuple(positions)

def searchBytesReferences(_bytes: bytes) -> list[Reference]:
    """
        搜索字节串的所有内存引用

        _bytes: 待搜索bytes
        return: list[搜索到的引用]
    """

    string_positions = searchBytes(_bytes, True)

    references = []
    for p in string_positions:
        for r in getReferencesTo(toRAMAddr(p)):
            references.append(r)

    return references

def searchUTF8StringReferences(string: str) -> list[Reference]:
    """
        将字符串进行UTF-16编码并搜索内存引用
    """
    return searchBytesReferences(string.encode('utf-8'))

def searchUTF16StringReferences(string: str) -> list[Reference]:
    """
        将字符串进行UTF-16编码并搜索内存引用
    """
    return searchBytesReferences(string.encode('utf-16'))


"""
    utility
"""
def searchStrParamings(strings: Iterable[str]) -> list[tuple[str, Function, int]]:
    """
        searchParamings -- 搜索常量串引用的函数参数
        Ghidra PARAM Reference + 向后搜索第一个引用

        searchStrParamings 搜索str作为函数参数的引用(方便, 但比searchBytesParamings慢, 因为需要尝试多种编码)
        return: list[(string, callee, callsite)]
    """
    paramings = []
    for s, r in searchMultiUTF8StringReferences(strings) + searchMultiUTF16StringReferences(strings):
        call =__searchCall(r.getFromAddress().getOffset())
        if (call is not None) and \
            (s, call[0], call[1]) not in paramings:
                paramings.append((s, call[0], call[1]))
    
    return paramings

def searchBytesParamings(strings: Iterable[bytes]) -> list[tuple[str, Function, int]]:
    """
        searchParamings -- 搜索常量串引用的函数参数
        Ghidra PARAM Reference + 向后搜索第一个引用

       searchBytesParamings: 搜索bytes作为函数参数的引用(比searchStrParamings快)
       return: list[(bytes, callee, callsite)]
    """
    paramings = []
    for w, r in searchMultiBytesReferences(strings):
        call =__searchCall(r.getFromAddress().getOffset())
        if (call is not None) and \
            (w, call[0], call[1]) not in paramings:
                paramings.append((w, call[0], call[1]))
    
    return paramings

reinit()

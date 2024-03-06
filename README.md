# search_string

Ghidra script 搜索常量字符串/字节串在内存中的使用 **单例**

## 接口
1. 常量引用: (getReferencesTo)
   1. `searchUTF8StringReferences`, `searchUTF16StringReferences`, `searchBytesReferences`
   2. `searchBytes`, `searchMultiBytesAC`
   3. 
2. 传参: `strcat(buffer, 'this is a string')`
   1. `searchStrParamings`, `searchBytesParamings`

## Examples

### 传参

```python
from search_string import searchBytesParamings

alphabet = [b'wksun', b'wkmon', b'wktue', b'wkwed', b'wkthu', b'wkfri', b'wksat']
for w, f, site in searchBytesParamings(alphabet):
    print(f'{site:08x}: {f.getName()}(\'{w}\')')

```

```
00441234: stringOut('b'wksun'')
00448246: stringOut('b'wkmon'')
00456476: stringOut('b'wksun'')
00458264: stringOut('b'wksat'')
```

### 常量引用

```python
from search_string import *

alphabet = [b'wksun', b'wkmon', b'wktue', b'wkwed', b'wkthu', b'wkfri', b'wksat']
for w, addr in searchMultiBytesAC(alphabet):
    print(f'{addr.getOffset():08x}: {w}')
```

```bash
004a1243: b'wktue'
004a1923: b'wkfri'
004c0484: b'wksun'
```
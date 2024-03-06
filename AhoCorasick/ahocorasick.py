from collections.abc import Iterable
from functools import reduce
from operator import add

class AhoCorasick:

    def __init__(self, words:Iterable[bytes]) -> None:
        """
            Trie树

            *words: 所有待匹配单词, 注意每个单词都是bytes

            TODO: _maxwordlength: 由于字典中单词一般不大, 考虑给出这个参数来压缩状态
        """
        self.fail = {}
        self.trie = {}

        self.finals = {}
        self.words = [w for w in words if len(w)]
        self.alphabet = set(reduce(add, self.words))
        self.__build()

    def __build(self):

        ### 构造前缀字典树
        self.trie[0] = dict()
        for w in self.words:
            failp = 0
            for i, b in enumerate(w):
                nxt = self.trie[failp].get(b)
                if nxt is None:
                    nxt = len(self.trie)
                    self.trie[failp][b] = nxt
                    self.trie[nxt] = dict()
                
                ### 是一个单词的结尾, 标明匹配到了一个单词
                if i == len(w) - 1:
                    self.finals[nxt] = w
                
                failp = nxt

        ### 构造fail指针
        for v in self.trie[0].values():
            self.fail[v] = 0
        q = list(self.trie[0].values())
        while q:
            p = q.pop(0)
            for b, u in self.trie[p].items():
                failp = self.fail[p]
                failto = self.trie[failp].get(b)
                while failto is None:
                    if failp == 0:
                        failto = 0
                        break
                    
                    failp = self.fail[failp]
                    failto = self.trie[failp].get(b) 

                self.fail[u] = failto
                q.append(u)
    
    def query(self, s: Iterable[int]) -> list[tuple[bytes, int]]:
        
        idx, p = -1, 0
        matched = []
        for b in s:
            
            idx += 1

            if b < 0 or b > 0xff:
                raise ValueError(f'invalid value of s[{idx}]: {hex(b)}')

            currp = p
            to = self.trie[currp].get(b)
            while to is None:

                if currp == 0:
                    to = 0
                    break
                
                currp = self.fail[currp]
                to = self.trie[currp].get(b)

            p = to

            if p in self.finals:
                matched.append((self.finals[p], idx-len(self.finals[p])+1))

        return matched

from collections.abc import Iterable

import numpy as np


class AhoCorasick:

    def __init__(self, words:Iterable[bytes]) -> None:
        """
            Trie树

            *words: 所有待匹配单词, 注意每个单词都是bytes

            TODO: _maxwordlength: 由于字典中单词一般不大, 考虑给出这个参数来压缩状态
        """

        self.finals = {}
        self.words = [w for w in words if len(w)]
        self.__build()

    def __build(self):
        

        ### 构造前缀字典树
        trie = {}
        trie[1] = dict()
        for w in self.words:
            failp = 1
            for i, b in enumerate(w):
                nxt = trie[failp].get(b)
                if nxt is None:
                    nxt = len(trie)+1
                    trie[failp][b] = nxt
                    trie[nxt] = dict()
                
                ### 是一个单词的结尾, 标明匹配到了一个单词
                if i == len(w) - 1:
                    self.finals[nxt] = w
                
                failp = nxt
        
        self.trie_matrix = np.zeros((len(trie)+1, 0x100), dtype=int)
        for u in trie:
            for b, v in trie[u].items():
                self.trie_matrix[u, b] = v

        ### 构造fail
        self.fail = np.zeros(len(trie)+1, dtype=int)
        for b in range(0, 0x100):
            self.trie_matrix[0, b] = 1
        self.fail[1] = 0
        q = [1]
        while q:
            u = q.pop(0)
            for b in range(0, 0x100):
                if self.trie_matrix[u, b]:
                    self.fail[self.trie_matrix[u, b]] = self.trie_matrix[self.fail[u], b]
                    q.append(self.trie_matrix[u, b])
                else:
                    self.trie_matrix[u, b] = self.trie_matrix[self.fail[u], b]

    
    def query(self, s: Iterable[int]) -> list[tuple[bytes, int]]:
        
        matched = []

        idx = -1
        u = 1
        for b in s:

            idx += 1
            if b < 0 or b > 0xff:
                raise ValueError(f'invalid value of s[{idx}]: {hex(b)}')
            
            u = self.trie_matrix[u, b]
            if u in self.finals:
                matched.append((self.finals[u], idx-len(self.finals[u])+1))
        
        return matched

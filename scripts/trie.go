package main

// TrieNode represents a node in the trie.
type TrieNode struct {
	children       map[rune]*TrieNode
	endOfWordCount int
}

// Trie represents the trie structure itself.
type Trie struct {
	root *TrieNode
}

// NewTrie creates and returns a new Trie.
func NewTrie() *Trie {
	return &Trie{
		root: &TrieNode{children: make(map[rune]*TrieNode)},
	}
}

// Insert inserts a word into the Trie.
func (t *Trie) Insert(word string) {
	node := t.root
	for _, char := range word {
		if _, exists := node.children[char]; !exists {
			node.children[char] = &TrieNode{children: make(map[rune]*TrieNode)}
		}
		node = node.children[char]
	}
	node.endOfWordCount++
}

// CountWordsWithPrefix counts how many words share the given prefix.
func (t *Trie) CountWordsWithPrefix(prefix string) int {
	node := t.root
	for _, char := range prefix {
		if _, exists := node.children[char]; !exists {
			return 0
		}
		node = node.children[char]
	}
	return countWordsInSubTrie(node)
}

// countWordsInSubTrie is a helper function that counts all words in the sub-trie.
func countWordsInSubTrie(node *TrieNode) int {
	count := node.endOfWordCount
	for _, child := range node.children {
		count += countWordsInSubTrie(child)
	}
	return count
}

// CountStandaloneOccurrences returns the end of word count for a specific prefix.
func (t *Trie) CountStandaloneOccurrences(prefix string) int {
	node := t.root
	for _, char := range prefix {
		if _, exists := node.children[char]; !exists {
			return 0
		}
		node = node.children[char]
	}
	return node.endOfWordCount
}

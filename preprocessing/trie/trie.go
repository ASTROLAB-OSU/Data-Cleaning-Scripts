package trie

import (
	"bufio"
	"log"
	"os"
	"strings"
)

// TrieNode represents a node in the trie.
type TrieNode struct {
	Children       map[rune]*TrieNode
	EndOfWordCount int
}

// Trie represents the trie structure itself.
type Trie struct {
	Root *TrieNode
}

// NewTrie creates and returns a new Trie.
func NewTrie() *Trie {
	return &Trie{
		Root: &TrieNode{Children: make(map[rune]*TrieNode)},
	}
}

// Insert inserts a word into the Trie.
func (t *Trie) Insert(word string) {
	node := t.Root
	for _, char := range word {
		if _, exists := node.Children[char]; !exists {
			node.Children[char] = &TrieNode{Children: make(map[rune]*TrieNode)}
		}
		node = node.Children[char]
	}
	node.EndOfWordCount++
}

// CountWordsWithPrefix counts how many words share the given prefix.
func (t *Trie) CountWordsWithPrefix(prefix string) int {
	node := t.Root
	for _, char := range prefix {
		if _, exists := node.Children[char]; !exists {
			return 0
		}
		node = node.Children[char]
	}
	return CountWordsInSubTrie(node)
}

// CountWordsInSubTrie is a helper function that counts all words in the sub-trie.
func CountWordsInSubTrie(node *TrieNode) int {
	count := node.EndOfWordCount
	for _, child := range node.Children {
		count += CountWordsInSubTrie(child)
	}
	return count
}

// CountStandaloneOccurrences returns the end of word count for a specific prefix.
func (t *Trie) CountStandaloneOccurrences(prefix string) int {
	node := t.Root
	for _, char := range prefix {
		if _, exists := node.Children[char]; !exists {
			return 0
		}
		node = node.Children[char]
	}
	return node.EndOfWordCount
}

// collectHighStandalone returns all prefixes with standalone occurrences above the threshold.
func CollectHighStandalone(passTrie *Trie, occurrenceThreshold int) []string {
	var highStandalonePrefixes []string
	CollectHighStandaloneRecursive(passTrie.Root, "", occurrenceThreshold, &highStandalonePrefixes)
	return highStandalonePrefixes
}

// Helper recursive function to traverse the trie and collect prefixes meeting the threshold.
func CollectHighStandaloneRecursive(node *TrieNode, currentPrefix string, occurrenceThreshold int, results *[]string) {
	// If this node marks the end of a word and meets the threshold, add it to the results.
	if node.EndOfWordCount > occurrenceThreshold {
		*results = append(*results, currentPrefix)
	}

	// Recursively check each child to continue building longer prefixes.
	for char, child := range node.Children {
		newPrefix := currentPrefix + string(char)
		CollectHighStandaloneRecursive(child, newPrefix, occurrenceThreshold, results)
	}
}

// LoadCredentialsFromFile loads passwords from a file and inserts them into the trie.
func LoadCredentialsFromFile(filePath string, passTrie *Trie) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file %s: %v", filePath, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		splitLine := strings.Split(line, ":")
		if len(splitLine) < 2 {
			continue
		}
		password := strings.TrimSpace(splitLine[1])
		if password != "" {
			passTrie.Insert(password)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading file %s: %v", filePath, err)
	}
}

// collectFollowingChars counts the occurrences of characters that follow the given prefix.
func CollectFollowingChars(passTrie *Trie, prefix string) map[rune]int {
	followingCharCount := make(map[rune]int)

	// Find the node for the given prefix
	node := passTrie.Root
	for _, char := range prefix {
		if _, exists := node.Children[char]; !exists {
			return followingCharCount // Return empty if the prefix doesn't exist
		}
		node = node.Children[char]
	}

	// Count all characters in the subtree that follow the prefix
	for childChar, childNode := range node.Children {
		// The count of this character is the count of all its words in the subtree
		count := CountWordsInSubTrie(childNode)
		followingCharCount[childChar] = count
	}

	return followingCharCount
}

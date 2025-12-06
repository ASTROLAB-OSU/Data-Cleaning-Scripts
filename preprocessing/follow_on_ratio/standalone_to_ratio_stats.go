package follow_on_ratio

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"preprocess/trie"
	"strings"
)

// PrefixStats represents statistics for a single prefix
type PrefixStats struct {
	Prefix          string `json:"prefix"`
	StandaloneCount int    `json:"standalone_count"`
	FollowingCount  int    `json:"following_count"`
}

// collectPrefixStats gathers statistics for all prefixes with standalone count > threshold
func collectPrefixStats(node *trie.TrieNode, currentPrefix string, threshold int, stats *[]PrefixStats) {
	if node.EndOfWordCount > threshold {
		// Calculate total following count
		totalFollowing := 0
		for _, child := range node.Children {
			totalFollowing += trie.CountWordsInSubTrie(child)
		}

		*stats = append(*stats, PrefixStats{
			Prefix:          currentPrefix,
			StandaloneCount: node.EndOfWordCount,
			FollowingCount:  totalFollowing,
		})
	}

	// Recursively process all Children
	for char, child := range node.Children {
		newPrefix := currentPrefix + string(char)
		collectPrefixStats(child, newPrefix, threshold, stats)
	}
}

func GeneratePrefixStatistics(srcDir string, outputFile string, occurrenceThreshold int) error {
	// Create a map to store stats for each file
	allStats := make(map[string][]PrefixStats)

	// Process all password files first
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.HasSuffix(info.Name(), "_passwords.txt") {
			fmt.Printf("Processing file: %s\n", info.Name())

			// Initialize trie for current file
			passTrie := trie.NewTrie()

			// Load credentials for the current file
			trie.LoadCredentialsFromFile(path, passTrie)

			// Collect statistics for this file's qualifying prefixes
			var stats []PrefixStats
			collectPrefixStats(passTrie.Root, "", occurrenceThreshold, &stats)

			// Store stats in map using filename as key
			baseName := strings.TrimSuffix(info.Name(), "_passwords.txt")
			allStats[baseName] = stats
		}
		return nil
	})

	if err != nil {
		return err
	}

	// Create output file for writing JSON
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer file.Close()

	// Write JSON with proper indentation
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(allStats); err != nil {
		return fmt.Errorf("error encoding JSON: %v", err)
	}

	return nil
}

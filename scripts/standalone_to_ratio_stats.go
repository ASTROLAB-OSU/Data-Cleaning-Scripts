package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// PrefixStats represents statistics for a single prefix
type PrefixStats struct {
	Prefix          string `json:"prefix"`
	StandaloneCount int    `json:"standalone_count"`
	FollowingCount  int    `json:"following_count"`
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

// collectPrefixStats gathers statistics for all prefixes with standalone count > threshold
func collectPrefixStats(node *TrieNode, currentPrefix string, threshold int, stats *[]PrefixStats) {
	if node.endOfWordCount > threshold {
		// Calculate total following count
		totalFollowing := 0
		for _, child := range node.children {
			totalFollowing += countWordsInSubTrie(child)
		}

		*stats = append(*stats, PrefixStats{
			Prefix:          currentPrefix,
			StandaloneCount: node.endOfWordCount,
			FollowingCount:  totalFollowing,
		})
	}

	// Recursively process all children
	for char, child := range node.children {
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
			passTrie := NewTrie()

			// Load credentials for the current file
			LoadCredentialsFromFile(path, passTrie)

			// Collect statistics for this file's qualifying prefixes
			var stats []PrefixStats
			collectPrefixStats(passTrie.root, "", occurrenceThreshold, &stats)

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

func main() {
	// Configuration
	srcDir := "../OrganizedPasswords"
	outputFile := "./data_cleaning/prefix_statistics.json"
	occurrenceThreshold := 1000

	err := GeneratePrefixStatistics(srcDir, outputFile, occurrenceThreshold)
	if err != nil {
		log.Fatalf("Error generating statistics: %v", err)
	}
}

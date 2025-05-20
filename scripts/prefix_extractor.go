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

/*

	Uses the character distrobution made to see what passwords have outliers

*/

// CharacterStats holds the statistical information for each character
type CharacterStats struct {
	Average  float64
	MinRange float64
	MaxRange float64
}

// Analysis thresholds
const (
	StandaloneThreshold     = 50000 // Minimum standalone occurrences to consider
	FollowingRatioThreshold = 0.001 // Maximum ratio of following/standalone occurrences to flag
)

// GlobalCharStats stores the baseline character distribution statistics
var GlobalCharStats = map[rune]CharacterStats{}

// LoadCharacterStats loads character distribution statistics from a JSON file into the global variable
func LoadCharacterStats(filePath string) error {
	// Open the JSON file
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Decode JSON into a temporary map
	var stats map[string]CharacterStats
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&stats); err != nil {
		return err
	}

	// Clear existing global stats
	GlobalCharStats = make(map[rune]CharacterStats)

	// Convert string keys to rune keys and populate global variable
	for key, value := range stats {
		if len(key) == 1 {
			GlobalCharStats[rune(key[0])] = value
		}
	}

	// Log the loaded stats for verification
	log.Printf("Loaded %d character distribution statistics", len(GlobalCharStats))
	return nil
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

// isDistributionOutlier checks if the character distribution for a prefix is an outlier
func isDistributionOutlier(char rune, percentage float64, stats CharacterStats) bool {
	return percentage > stats.MaxRange
}

// isHighStandaloneWithFewFollowing checks if a prefix has many standalone occurrences but few following characters
func isHighStandaloneWithFewFollowing(standaloneCount int, totalFollowingCount int) bool {
	if standaloneCount < StandaloneThreshold {
		return false
	}

	// Calculate the ratio of following occurrences to standalone occurrences
	ratio := float64(totalFollowingCount) / float64(standaloneCount)
	return ratio < FollowingRatioThreshold
}

// ScanForSuspiciousPrefixes processes password files and logs suspicious prefixes.
func ScanForSuspiciousPrefixes(srcDir string, distributionFile string, occurrenceThreshold int) {
	distFile, err := os.Create(distributionFile)

	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer distFile.Close()

	distWriter := bufio.NewWriter(distFile)

	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error accessing file %s: %v", path, err)
			return nil
		}
		if strings.HasSuffix(info.Name(), "_passwords.txt") {
			fmt.Printf("Processing file: %s\n", info.Name())

			passTrie := NewTrie()
			LoadCredentialsFromFile(path, passTrie)
			highStandalone := collectHighStandalone(passTrie, occurrenceThreshold)

			// Write file header
			distWriter.WriteString("=== Analysis Results For " + info.Name() + " ===\n\n")
			distWriter.WriteString("------------------------\n\n")

			// First pass: Check for distribution outliers
			for _, prefix := range highStandalone {
				followingCharCount := collectFollowingChars(passTrie, prefix)
				totalFollowingCount := 0
				outlierFound := false

				for _, count := range followingCharCount {
					totalFollowingCount += count
				}

				// Check for outlier distributions
				var outlierChars []string
				for char, count := range followingCharCount {
					if stats, exists := GlobalCharStats[char]; exists {
						percentage := float64(count) / float64(totalFollowingCount)
						if isDistributionOutlier(char, percentage, stats) {
							if percentage > 0.005 {
								outlierFound = true
								outlierChars = append(outlierChars, fmt.Sprintf("'%c' (%.4f%%)", char, percentage*100))
							}
						}
					}
				}

				// Only write prefixes that have outlier distributions
				if outlierFound {
					standaloneCount := passTrie.CountStandaloneOccurrences(prefix)
					_, err := distWriter.WriteString(fmt.Sprintf("Prefix: '%s'\n", prefix))
					if err != nil {
						log.Printf("Error writing to file: %v", err)
					}

					distWriter.WriteString(fmt.Sprintf("    Standalone occurrences: %d\n", standaloneCount))
					distWriter.WriteString(fmt.Sprintf("    Total following occurrences: %d\n", totalFollowingCount))
					distWriter.WriteString(fmt.Sprintf("    Outlier characters found: %s\n", strings.Join(outlierChars, ", ")))

					distWriter.WriteString("\n")
				}
			}

			distWriter.Flush()
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error walking through directory: %v", err)
	}

	fmt.Printf("Suspicious prefixes have been logged in %s\n", distributionFile)
}

// collectHighStandalone returns all prefixes with standalone occurrences above the threshold.
func collectHighStandalone(passTrie *Trie, occurrenceThreshold int) []string {
	var highStandalonePrefixes []string
	collectHighStandaloneRecursive(passTrie.root, "", occurrenceThreshold, &highStandalonePrefixes)
	return highStandalonePrefixes
}

// Helper recursive function to traverse the trie and collect prefixes meeting the threshold.
func collectHighStandaloneRecursive(node *TrieNode, currentPrefix string, occurrenceThreshold int, results *[]string) {
	// If this node marks the end of a word and meets the threshold, add it to the results.
	if node.endOfWordCount > occurrenceThreshold {
		*results = append(*results, currentPrefix)
	}

	// Recursively check each child to continue building longer prefixes.
	for char, child := range node.children {
		newPrefix := currentPrefix + string(char)
		collectHighStandaloneRecursive(child, newPrefix, occurrenceThreshold, results)
	}
}

// collectFollowingChars counts the occurrences of characters that follow the given prefix.
func collectFollowingChars(passTrie *Trie, prefix string) map[rune]int {
	followingCharCount := make(map[rune]int)

	// Find the node for the given prefix
	node := passTrie.root
	for _, char := range prefix {
		if _, exists := node.children[char]; !exists {
			return followingCharCount // Return empty if the prefix doesn't exist
		}
		node = node.children[char]
	}

	// Now count all characters in the subtree that follow the prefix
	for childChar, childNode := range node.children {
		// The count of this character is the count of all its words in the subtree
		count := countWordsInSubTrie(childNode)
		followingCharCount[childChar] = count
	}

	return followingCharCount
}

func main() {
	// Specify the file paths and threshold
	passwordFile := "../OrganizedPasswords/"
	distributionFile := "suspicious_distributions.txt"
	occurrenceThreshold := 1000

	err := LoadCharacterStats("../char_distributions.json")
	if err != nil {
		log.Fatalf("Failed to load character stats: %v", err)
	}

	// Extract patterns and save them to a file
	ScanForSuspiciousPrefixes(passwordFile, distributionFile, occurrenceThreshold)

	fmt.Printf("Patterns extracted to %s\n", distributionFile)
}

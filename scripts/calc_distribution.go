package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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

// Global map to aggregate distributions for each character
var globalCharDistributions = make(map[rune][]float64)

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

	// Count all characters in the subtree that follow the prefix
	for childChar, childNode := range node.children {
		// The count of this character is the count of all its words in the subtree
		count := countWordsInSubTrie(childNode)
		followingCharCount[childChar] = count
	}

	return followingCharCount
}

// aggregateCharacterDistributions updates the global distribution map for each character.
func aggregateCharacterDistributions(distributions map[rune]int, total int) {
	for char, count := range distributions {
		percentage := (float64(count) / float64(total)) * 100
		globalCharDistributions[char] = append(globalCharDistributions[char], percentage)
	}
}

// calculateAverageAndRange computes the average, 25th, and 75th percentiles for each character.
func calculateAverageAndRange() map[rune]map[string]float64 {
	result := make(map[rune]map[string]float64)

	for char, percentages := range globalCharDistributions {
		sort.Float64s(percentages)
		average := calculateAverage(percentages)
		lowerQuartile := calculatePercentile(percentages, 5)
		upperQuartile := calculatePercentile(percentages, 95)

		result[char] = map[string]float64{
			"average":        average,
			"lower_quartile": lowerQuartile,
			"upper_quartile": upperQuartile,
		}
	}

	return result
}

// Helper function to calculate the average of a slice.
func calculateAverage(data []float64) float64 {
	sum := 0.0
	for _, value := range data {
		sum += value
	}
	return sum / float64(len(data))
}

// Helper function to calculate a specific percentile from a sorted slice.
func calculatePercentile(data []float64, percentile int) float64 {
	index := (percentile * len(data)) / 100
	if index >= len(data) {
		index = len(data) - 1
	}
	return data[index]
}

// ScanForCharacterDistributions processes password files and computes global character distributions.
func ScanForCharacterDistributions(srcDir string, outputFile string, occurrenceThreshold int) {
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error accessing file %s: %v", path, err)
			return nil
		}
		if strings.HasSuffix(info.Name(), "_passwords.txt") {
			fmt.Printf("Processing file: %s\n", info.Name())

			// Reset the Trie for each file.
			passTrie := NewTrie()

			// Load passwords into the Trie.
			LoadCredentialsFromFile(path, passTrie)

			// Get prefixes with high standalone occurrences.
			highStandalone := collectHighStandalone(passTrie, occurrenceThreshold)

			// Aggregate character distributions across all prefixes.
			for _, prefix := range highStandalone {
				followingCharCount := collectFollowingChars(passTrie, prefix)

				// Calculate total following characters for the prefix.
				totalFollowingCount := 0
				for _, count := range followingCharCount {
					totalFollowingCount += count
				}

				if totalFollowingCount > 0 {
					aggregateCharacterDistributions(followingCharCount, totalFollowingCount)
				}
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error walking through directory: %v", err)
	}

	// Write the final averages and ranges to the output file.
	writeFinalStatistics(outputFile)
}

func writeFinalStatistics(outputFile string) {
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	stats := calculateAverageAndRange()

	for char, stat := range stats {
		_, err := writer.WriteString(fmt.Sprintf(
			"Character: '%c' - Average: %.2f%% - Range: [%.2f%%, %.2f%%]\n",
			char, stat["average"], stat["lower_quartile"], stat["upper_quartile"]))
		if err != nil {
			log.Printf("Error writing to file: %v", err)
		}
	}

	writer.Flush()
	fmt.Printf("Character distributions logged to %s\n", outputFile)
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

func main() {
	// Specify the file paths and threshold
	passwordFile := "OrganizedPasswords"
	outputFile := "character_distributions.txt"
	occurrenceThreshold := 50000

	// Process files and compute distributions
	ScanForCharacterDistributions(passwordFile, outputFile, occurrenceThreshold)

	fmt.Printf("Character distributions logged to %s\n", outputFile)
}

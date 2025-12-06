package follow_on_distribution

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"preprocess/trie"
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

// isDistributionOutlier checks if the character distribution for a prefix is an outlier
func isDistributionOutlier(char rune, percentage float64, stats CharacterStats) bool {
	return percentage > stats.MaxRange
}

// isHighStandaloneWithFewFollowing checks if a prefix has many standalone occurrences but few following characters
func isHighStandaloneWithFewFollowing(standaloneCount int, totalFollowingCount int) bool {
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

			passTrie := trie.NewTrie()
			trie.LoadCredentialsFromFile(path, passTrie)
			highStandalone := trie.CollectHighStandalone(passTrie, occurrenceThreshold)

			// Write CSV header for the first file
			if info.Name() == filepath.Base(path) {
				distWriter.WriteString("File,Prefix,Standalone_Occurrences,Total_Following,Outlier_Characters,Outlier_Percentages\n")
			}

			// First pass: Check for distribution outliers
			for _, prefix := range highStandalone {
				followingCharCount := trie.CollectFollowingChars(passTrie, prefix)
				totalFollowingCount := 0
				outlierFound := false

				for _, count := range followingCharCount {
					totalFollowingCount += count
				}

				// Check for outlier distributions
				var outlierChars []string
				var outlierPercentages []string
				for char, count := range followingCharCount {
					if stats, exists := GlobalCharStats[char]; exists {
						percentage := float64(count) / float64(totalFollowingCount)
						if isDistributionOutlier(char, percentage, stats) {
							if percentage > 0.005 {
								outlierFound = true
								outlierChars = append(outlierChars, string(char))
								outlierPercentages = append(outlierPercentages, fmt.Sprintf("%.4f", percentage*100))
							}
						}
					}
				}

				// Only write prefixes that have outlier distributions in CSV format
				if outlierFound {
					standaloneCount := passTrie.CountStandaloneOccurrences(prefix)
					// Escape quotes in prefix if any
					escapedPrefix := strings.ReplaceAll(prefix, "\"", "\"\"")
					_, err := distWriter.WriteString(fmt.Sprintf("%s,\"%s\",%d,%d,\"%s\",\"%s\"\n",
						info.Name(),
						escapedPrefix,
						standaloneCount,
						totalFollowingCount,
						strings.Join(outlierChars, "|"),
						strings.Join(outlierPercentages, "|")))
					if err != nil {
						log.Printf("Error writing to file: %v", err)
					}
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

func Prefix_extractor(passwordFile, susDistributionFile, charDistributionFile string, occurrenceThreshold int) {

	err := LoadCharacterStats(charDistributionFile)
	if err != nil {
		log.Fatalf("Failed to load character stats: %v", err)
	}

	// Extract patterns and save them to a file
	ScanForSuspiciousPrefixes(passwordFile, susDistributionFile, occurrenceThreshold)

	fmt.Printf("Patterns have been saved to %s in CSV format\n", susDistributionFile)
}

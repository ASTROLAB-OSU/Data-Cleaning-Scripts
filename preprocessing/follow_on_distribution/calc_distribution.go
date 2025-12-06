package follow_on_distribution

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"preprocess/trie"
	"sort"
	"strings"
)

type Dist struct {
	Average  float64 `json:"Average"`
	MinRange float64 `json:"MinRange"`
	MaxRange float64 `json:"MaxRange"`
}

// Global map to aggregate distributions for each character
var globalCharDistributions = make(map[rune][]float64)

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
func ScanForCharacterDistributions(srcDir string, occurrenceThreshold int) map[string]Dist {
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error accessing file %s: %v", path, err)
			return nil
		}
		if strings.HasSuffix(info.Name(), "_passwords.txt") {
			fmt.Printf("Processing file: %s\n", info.Name())

			passTrie := trie.NewTrie()
			trie.LoadCredentialsFromFile(path, passTrie)
			highStandalone := trie.CollectHighStandalone(passTrie, occurrenceThreshold)

			for _, prefix := range highStandalone {
				followingCharCount := trie.CollectFollowingChars(passTrie, prefix)

				totalFollowingCount := 0
				for _, c := range followingCharCount {
					totalFollowingCount += c
				}

				if totalFollowingCount > 0 {
					aggregateCharacterDistributions(followingCharCount, totalFollowingCount)
				}
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error walking directory: %v", err)
	}

	return calculateFinalStatistics()
}

func calculateFinalStatistics() map[string]Dist {
	stats := calculateAverageAndRange()

	result := make(map[string]Dist)
	for char, stat := range stats {
		result[string(char)] = Dist{
			Average:  stat["average"] / 100,
			MinRange: stat["lower_quartile"] / 100,
			MaxRange: stat["upper_quartile"] / 100,
		}
	}
	return result
}

func Calc_distribution(inputDir, outputJSON string) {
	occurrenceThreshold := 50000

	// Run the scan and get the final statistics as a map
	result := ScanForCharacterDistributions(inputDir, occurrenceThreshold)

	// Save JSON directly
	out, err := os.Create(outputJSON)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer out.Close()

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(result); err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}

	fmt.Printf("JSON distribution saved to %s\n", outputJSON)
}

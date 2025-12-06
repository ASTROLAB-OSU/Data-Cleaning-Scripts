package main

import (
	"log"
	"preprocess/follow_on_ratio"
)

func main() {
	// Configuration
	srcDir := "../../results/OrganizedPasswords"
	outputFile := "../../results/data_cleaning/prefix_statistics.json"
	occurrenceThreshold := 1000

	err := follow_on_ratio.GeneratePrefixStatistics(srcDir, outputFile, occurrenceThreshold)
	if err != nil {
		log.Fatalf("Error generating statistics: %v", err)
	}
}

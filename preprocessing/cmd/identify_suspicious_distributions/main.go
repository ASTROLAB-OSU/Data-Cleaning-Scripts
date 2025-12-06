package main

import "preprocess/follow_on_distribution"

// real one
func main() {
	inputDir := "../../results/OrganizedPasswords"
	outputJSON := "../../results/char_distributions.json"
	distributionFile := "../../results/suspicious_distributions.csv"
	occurrenceThreshold := 110000

	follow_on_distribution.Calc_distribution(inputDir, outputJSON)
	follow_on_distribution.Prefix_extractor(inputDir, distributionFile, outputJSON, occurrenceThreshold)
}

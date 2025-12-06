package main

import (
	"preprocess/follow_on_ratio"
)

func main() {
	inputFile := "../../results/prefix_statistics.json"
	outputFile := "../../results/for_passwords.json"

	follow_on_ratio.IdentifySuspiciousRatios(inputFile, outputFile)

}

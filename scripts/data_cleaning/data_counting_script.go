package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

// SeqInfo holds tracking info for sequential usernames.
type SeqInfo struct {
	lastNumber   int
	count        int
	startRemoval bool
}

// CleaningStats stores counts of what would be removed by each method
type CleaningStats struct {
	priorWorkRemovals       int
	ruleBasedRemovals       int
	suspiciousEmailRemovals int
	fodRemovals             int
	forRemovals             int
	fbobRemovals            int
	totalProcessed          int
}

var (
	// allowedControlChars: only tab (9), newline (10), and carriage return (13) are allowed below 32.
	allowedControlChars = map[rune]bool{9: true, 10: true, 13: true}
	// sequentialUsernames maps "base@domain" to sequence information.
	sequentialUsernames = make(map[string]SeqInfo)
	// Global stats to track removals across all files
	globalStats = CleaningStats{}
)

// checkFBOB detects entries that would be removed for having fbobh_ prefix without removing them
func checkFBOB(usernames, passwords []string, removedFBOB *[]string) int {
	count := 0
	for idx, pwd := range passwords {
		if strings.HasPrefix(pwd, "fbobh_") {
			*removedFBOB = append(*removedFBOB, fmt.Sprintf("%s:%s", usernames[idx], pwd))
			count++
		}
	}
	return count
}

// detectSequentialUsernames detects sequences of 100 or more usernames with an incrementing number suffix
func detectSequentialUsernames(email string, sequentialUsernames map[string]SeqInfo) bool {
	re := regexp.MustCompile(`^([a-zA-Z0-9._%+\-]+?)(\d+)@(.+)$`)
	matches := re.FindStringSubmatch(email)
	if matches == nil || len(matches) < 4 {
		return false
	}

	baseName := matches[1]
	numberStr := matches[2]
	domain := matches[3]
	number, err := strconv.Atoi(numberStr)
	if err != nil {
		return false
	}

	key := fmt.Sprintf("%s@%s", baseName, domain)

	if seq, exists := sequentialUsernames[key]; exists {
		if number == seq.lastNumber+1 {
			seq.count++
			seq.startRemoval = seq.startRemoval || (seq.count >= 100)
			seq.lastNumber = number
			sequentialUsernames[key] = seq
		} else {
			sequentialUsernames[key] = SeqInfo{lastNumber: number, count: 1, startRemoval: false}
		}
	} else {
		sequentialUsernames[key] = SeqInfo{lastNumber: number, count: 1, startRemoval: false}
	}

	return sequentialUsernames[key].startRemoval
}

// priorWorkChecks performs various checks on a credential line and returns true if the credential passes.
func priorWorkChecks(credential, email, password string, removedPriorWorks *[]string) bool {
	trimCred := strings.TrimSpace(credential)
	// Check for non-ascii characters outside allowed control chars.
	for _, r := range credential {
		if (r < 32 && !allowedControlChars[r]) || r > 126 {
			*removedPriorWorks = append(*removedPriorWorks, trimCred)
			return false
		}
	}
	// Check password length constraints.
	if len(password) < 4 || len(password) > 30 {
		*removedPriorWorks = append(*removedPriorWorks, trimCred)
		return false
	}
	// Check if password is all hexadecimal when long enough.
	if len(password) >= 20 {
		allHex := true
		for _, ch := range password {
			if !strings.ContainsRune("0123456789abcdefABCDEF", ch) {
				allHex = false
				break
			}
		}
		if allHex {
			*removedPriorWorks = append(*removedPriorWorks, trimCred)
			return false
		}
	}
	return true
}

// checkRuleBased counts credentials that would be removed by rule-based filters without removing them
func checkRuleBased(usernames, passwords []string, removedRuleBased *[]string) int {
	count := 0

	// Track duplicates
	duplicates := make(map[string]int)
	emailDuplicates := make(map[string]int)

	// Process each credential
	for i := range usernames {
		email := usernames[i]
		password := passwords[i]
		credential := fmt.Sprintf("%s:%s", email, password)
		shouldRemove := false

		// Check sequential username rule
		if detectSequentialUsernames(email, sequentialUsernames) {
			shouldRemove = true
		}

		// Check for duplicate credentials
		duplicates[credential]++
		if duplicates[credential] > 1 {
			shouldRemove = true
		}

		// Check if the same email appears more than 100 times
		emailDuplicates[email]++
		if emailDuplicates[email] > 100 {
			shouldRemove = true
		}

		// Validate email format
		emailRe := regexp.MustCompile(`^[_a-zA-Z0-9\-]+(\.[_a-zA-Z0-9\-]+)*@[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)*(\.[a-zA-Z]{2,4})$`)
		if !emailRe.MatchString(email) {
			shouldRemove = true
		}

		// Check email length
		if len(email) < 10 || len(email) > 40 {
			shouldRemove = true
		}

		if shouldRemove {
			*removedRuleBased = append(*removedRuleBased, credential)
			count++
		}
	}

	return count
}

// priorWorksCleaning processes one file: it reads the file (using latin1 decoding),
// checks each line, and returns the valid credentials and count of removed ones.
func priorWorksCleaning(filePath string, usernames *[]string, passwords *[]string, removedPriorWorks *[]string) (int, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	fmt.Println("Currently processing: " + filePath)

	removedCount := 0
	totalEntries := 0

	decoder := charmap.ISO8859_1.NewDecoder()
	reader := decoder.Reader(f)
	scanner := bufio.NewScanner(reader)
	// Increase maximum token size if needed.
	buf := make([]byte, 1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		var parts []string
		if strings.Contains(line, ":") {
			parts = strings.Split(line, ":")
		} else if strings.Contains(line, ";") {
			parts = strings.Split(line, ";")
		} else {
			continue
		}
		if len(parts) < 2 {
			continue
		}

		totalEntries++
		username := parts[0]
		password := strings.TrimSpace(parts[1])

		if priorWorkChecks(line, username, password, removedPriorWorks) {
			*usernames = append(*usernames, username)
			*passwords = append(*passwords, password)
		} else {
			removedCount++
		}
	}

	return removedCount, scanner.Err()
}

// processFile handles a single file: it analyzes the file for potential removals
// and writes all credentials to the destination file.
func processFile(srcPath, destPath string) error {
	var usernames []string
	var passwords []string
	var removedPriorWorks []string
	var removedRuleBased []string
	var removedSuspiciousEmail []string
	var removedFod []string
	var removedFor []string
	var removedFBOB []string

	fileStats := CleaningStats{}

	// Process the file and count prior work removals
	priorWorkRemovals, err := priorWorksCleaning(srcPath, &usernames, &passwords, &removedPriorWorks)
	if err != nil {
		return err
	}
	fileStats.priorWorkRemovals = priorWorkRemovals
	fileStats.totalProcessed = len(usernames) + priorWorkRemovals

	// Count other potential removals without actually removing entries
	fileStats.ruleBasedRemovals = checkRuleBased(usernames, passwords, &removedRuleBased)
	_, _ = removeSuspiciousEmails(usernames, passwords, &removedSuspiciousEmail)
	fileStats.suspiciousEmailRemovals = len(removedSuspiciousEmail)
	_, _, _ = removeSuspiciousFollowOnRatios(usernames, passwords, &removedFor)
	fileStats.forRemovals = len(removedFor)
	_, _ = removeSuspiciousFollowOnDistrobution(usernames, passwords, &removedFod)
	fileStats.fodRemovals = len(removedFod)
	fileStats.fbobRemovals = checkFBOB(usernames, passwords, &removedFBOB)

	// Update global statistics
	globalStats.totalProcessed += fileStats.totalProcessed
	globalStats.priorWorkRemovals += fileStats.priorWorkRemovals
	globalStats.ruleBasedRemovals += fileStats.ruleBasedRemovals
	globalStats.forRemovals += fileStats.forRemovals
	globalStats.fbobRemovals += fileStats.fbobRemovals

	// Write all credentials to destination
	outFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(outFile)
	for i := range usernames {
		if _, err := writer.WriteString(fmt.Sprintf("%s:%s\n", usernames[i], passwords[i])); err != nil {
			outFile.Close()
			return err
		}
	}
	writer.Flush()
	outFile.Close()

	// Output stats for this file
	fmt.Printf("\nFile statistics for %s:\n", filepath.Base(srcPath))
	fmt.Printf("Total entries processed: %d\n", fileStats.totalProcessed)
	fmt.Printf("Prior work checks would remove: %d (%.2f%%)\n",
		fileStats.priorWorkRemovals,
		percentage(fileStats.priorWorkRemovals, fileStats.totalProcessed))
	fmt.Printf("Rule-based checks would remove: %d (%.2f%%)\n",
		fileStats.ruleBasedRemovals,
		percentage(fileStats.ruleBasedRemovals, fileStats.totalProcessed))
	fmt.Printf("Follow-on ratio checks would remove: %d (%.2f%%)\n",
		fileStats.forRemovals,
		percentage(fileStats.forRemovals, fileStats.totalProcessed))
	fmt.Printf("FBOB checks would remove: %d (%.2f%%)\n",
		fileStats.fbobRemovals,
		percentage(fileStats.fbobRemovals, fileStats.totalProcessed))

	// Log removed entries if needed (optional)
	// Uncomment these if you still want to keep track of what would be removed
	logRemovals("/home/lucas/Data-Cleaning/CleanedBreach/removed_prior_work.txt", removedPriorWorks)
	logRemovals("/home/lucas/Data-Cleaning/CleanedBreach/removed_rule_based.txt", removedRuleBased)
	logRemovals("/home/lucas/Data-Cleaning/CleanedBreach/removed_suspicious_email.txt", removedSuspiciousEmail)
	logRemovals("/home/lucas/Data-Cleaning/CleanedBreach/removed_for.txt", removedFor)
	logRemovals("/home/lucas/Data-Cleaning/CleanedBreach/removed_fod.txt", removedFod)
	logRemovals("/home/lucas/Data-Cleaning/CleanedBreach/removed_FBOB.txt", removedFBOB)

	return nil
}

// Helper function to calculate percentage
func percentage(count, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(count) * 100 / float64(total)
}

// Helper function to log what would be removed
func logRemovals(logPath string, entries []string) error {
	if len(entries) == 0 {
		return nil
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, entry := range entries {
		if _, err := f.WriteString(entry + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// recreateDirectoryStructure walks through srcDir, and for each file processes it individually.
func recreateDirectoryStructure(srcDir, destDir string) error {
	// Walk the source directory.
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Determine relative path.
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(destDir, relPath)
		// If directory, ensure it exists in destination.
		if info.IsDir() {
			return os.MkdirAll(destPath, os.ModePerm)
		}
		// Process individual file.
		if err := processFile(path, destPath); err != nil {
			return err
		}
		return nil
	})

	return err
}

func main() {
	sourceDirectory := "/home/lucas/Data-Cleaning/data"
	destinationDirectory := "/home/lucas/Data-Cleaning/CleanedBreach/data"

	if err := recreateDirectoryStructure(sourceDirectory, destinationDirectory); err != nil {
		log.Fatalf("Error processing directories: %v", err)
	}
	fmt.Println("Processing complete.")
}

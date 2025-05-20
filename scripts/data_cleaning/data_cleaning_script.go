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

var (
	// allowedControlChars: only tab (9), newline (10), and carriage return (13) are allowed below 32.
	allowedControlChars = map[rune]bool{9: true, 10: true, 13: true}
	// sequentialUsernames maps "base@domain" to sequence information.
	sequentialUsernames = make(map[string]SeqInfo)
)

// remove fbobh_ entries
func removeFBOB(usernames, passwords []string, removedFBOB *[]string) ([]string, []string) {
	// Process each credential.
	var newUsernames, newPasswords []string
	for idx, pwd := range passwords {
		if strings.HasPrefix(pwd, "fbobh_") {
			*removedFBOB = append(*removedFBOB, fmt.Sprintf("%s:%s", usernames[idx], pwd))
		} else {
			newUsernames = append(newUsernames, usernames[idx])
			newPasswords = append(newPasswords, pwd)
		}
	}
	return newUsernames, newPasswords
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

func removeRuleBased(usernames, passwords []string, removedRuleBased *[]string) ([]string, []string) {
	// Prepare output lists
	filteredUsernames := []string{}
	filteredPasswords := []string{}

	// Track duplicates
	duplicates := make(map[string]int)
	emailDuplicates := make(map[string]int)

	// Process each credential
	for i := range usernames {
		email := usernames[i]
		password := passwords[i]
		credential := fmt.Sprintf("%s:%s", email, password)

		// Check for duplicate credentials
		duplicates[credential]++
		if duplicates[credential] > 1 {
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// Check email length
		if len(email) < 10 || len(email) > 40 {
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// Validate email format
		emailRe := regexp.MustCompile(`^[_a-zA-Z0-9\-]+(\.[_a-zA-Z0-9\-]+)*@[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)*(\.[a-zA-Z]{2,4})$`)
		if !emailRe.MatchString(email) {
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// Check if the same email appears more than 100 times
		emailDuplicates[email]++
		if emailDuplicates[email] > 100 {
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// Check sequential username rule
		if detectSequentialUsernames(email, sequentialUsernames) {
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// If all checks pass, add to filtered lists
		filteredUsernames = append(filteredUsernames, email)
		filteredPasswords = append(filteredPasswords, password)
	}

	return filteredUsernames, filteredPasswords
}

// priorWorksCleaning processes one file: it reads the file (using latin1 decoding),
// checks each line, and writes the cleaned credentials to memory (returned as slices).
// It also appends any removed entries to removedpriorWorks.
func priorWorksCleaning(filePath string, usernames *[]string, passwords *[]string, removedPriorWorks *[]string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Println("Currently processing: " + filePath)

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
		username := parts[0]
		password := strings.TrimSpace(parts[1])
		if priorWorkChecks(line, username, password, removedPriorWorks) {
			*usernames = append(*usernames, username)
			*passwords = append(*passwords, password)
		}
	}
	return scanner.Err()
}

// processFile handles a single file: it runs rule-based cleaning,
// writes the cleaned credentials to the destination file, and appends any removed entries to a log file.
func processFile(srcPath, destPath string) error {
	var usernames []string
	var passwords []string
	var removedPriorWorks []string
	var removedRuleBased []string
	var removedSuspiciousEmail []string
	var removedFod []string
	var removedFor []string
	var removedFBOB []string

	// Process the file and do previous work cleaning.
	if err := priorWorksCleaning(srcPath, &usernames, &passwords, &removedPriorWorks); err != nil {
		return err
	}

	// extra rule based
	usernames, passwords = removeRuleBased(usernames, passwords, &removedRuleBased)

	// Call the suspicious emails cleaning function.
	usernames, passwords = removeSuspiciousEmails(usernames, passwords, &removedSuspiciousEmail)

	// Call remove follow on distribution cleaning
	usernames, passwords = removeSuspiciousFollowOnDistribution(usernames, passwords, &removedFod)

	// Call remove follow on ratio cleaning
	usernames, passwords, _ = removeSuspiciousFollowOnRatios(usernames, passwords, &removedFor)

	// Call remove FBOB
	usernames, passwords = removeFBOB(usernames, passwords, &removedFBOB)

	// Write cleaned credentials to destination.
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

	// add prior work removed to the log file.
	if len(removedPriorWorks) > 0 {
		f, err := os.OpenFile("/home/lucas/Data-Cleaning/CleanedBreach/removed_prior_work.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		for _, entry := range removedPriorWorks {
			if _, err := f.WriteString(entry + "\n"); err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
	}

	// Append removed rule based entries to the log file.
	if len(removedRuleBased) > 0 {
		f, err := os.OpenFile("/home/lucas/Data-Cleaning/CleanedBreach/removed_rule_based.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		for _, entry := range removedRuleBased {
			if _, err := f.WriteString(entry + "\n"); err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
	}

	// Append removed email based entries to the log file.
	if len(removedSuspiciousEmail) > 0 {
		f, err := os.OpenFile("/home/lucas/Data-Cleaning/CleanedBreach/removed_suspicious_email.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		for _, entry := range removedSuspiciousEmail {
			if _, err := f.WriteString(entry + "\n"); err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
	}

	// Append removed FOd entries to the log file.
	if len(removedFod) > 0 {
		f, err := os.OpenFile("/home/lucas/Data-Cleaning/CleanedBreach/removed_fod.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		for _, entry := range removedFod {
			if _, err := f.WriteString(entry + "\n"); err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
	}

	// Append removed FOd entries to the log file.
	if len(removedFor) > 0 {
		f, err := os.OpenFile("/home/lucas/Data-Cleaning/CleanedBreach/removed_for.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		for _, entry := range removedFor {
			if _, err := f.WriteString(entry + "\n"); err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
	}

	// Append removed FBOB entries to the log file
	if len(removedFBOB) > 0 {
		f, err := os.OpenFile("/home/lucas/Data-Cleaning/CleanedBreach/removed_FBOB.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		for _, entry := range removedFBOB {
			if _, err := f.WriteString(entry + "\n"); err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
	}
	return nil
}

// recreateDirectoryStructure walks through srcDir, and for each file processes it individually.
func recreateDirectoryStructure(srcDir, destDir string) error {
	// Walk the source directory.
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
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
}

func main() {
	sourceDirectory := "/home/lucas/Data-Cleaning/data"
	destinationDirectory := "/home/lucas/Data-Cleaning/CleanedBreach/data"

	if err := recreateDirectoryStructure(sourceDirectory, destinationDirectory); err != nil {
		log.Fatalf("Error processing directories: %v", err)
	}
	fmt.Println("Processing complete.")
}

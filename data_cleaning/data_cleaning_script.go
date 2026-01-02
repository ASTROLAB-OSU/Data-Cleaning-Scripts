package main

import (
	"Data-Cleaning/cleaning"
	"Data-Cleaning/config"
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var TLD_SET map[string]bool

var (
	// Global Stats to track removals across all files
	globalStats  = config.CleaningStats{}
	breachConfig = config.BreachConfig{}
	statsLock    sync.Mutex // Protect global stats in parallel mode
	// Flag to control breach
	breachName = flag.String("breach", "", "Specify which breach from the config should be cleaned)")
	// Flag to control mode
	dryRun = flag.Bool("dry-run", false, "Count what would be removed without actually removing (independent analysis)")
	// Number of parallel workers for dry-run mode
	workers = flag.Int("workers", 10, "Number of parallel workers")
	// Name of removal summary file
	logSummary = "removal_summary.txt"
)

// Initialize TLD_SET from file
func loadTLDs(tldfile string) error {
	TLD_SET = make(map[string]bool)

	file, err := os.Open(tldfile)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		tld := strings.ToLower(strings.TrimSpace(scanner.Text()))
		TLD_SET[tld] = true
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}

// fileJob represents a file to process
type fileJob struct {
	srcPath  string
	destPath string
	logPath  string
}

// More memory-efficient version that explicitly clears large slices
func processFile(srcPath, destPath, logPath string) error {
	// Ensure destination directory exists
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %v", destDir, err)
	}

	// Check if destination path exists and is a directory
	if info, err := os.Stat(destPath); err == nil && info.IsDir() {
		return fmt.Errorf("destination path %s is a directory, cannot write file there", destPath)
	}

	fmt.Println("Currently processing: " + srcPath)

	// Read the entire file once to get original data
	var originalUsernames []string
	var originalPasswords []string

	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 1024)
	maxTokenSize := 10 * 1024 * 1024
	scanner.Buffer(buf, maxTokenSize)

	for scanner.Scan() {
		line := scanner.Text()
		user := ""
		pass := ""

		if idx := strings.Index(line, ":"); idx != -1 {
			user = line[:idx]
			pass = line[idx+1:]
		} else if idx := strings.Index(line, ";"); idx != -1 {
			user = line[:idx]
			pass = line[idx+1:]
		} else {
			continue
		}

		originalUsernames = append(originalUsernames, strings.ToLower(user))
		originalPasswords = append(originalPasswords, pass)
	}

	f.Close()
	if err := scanner.Err(); err != nil {
		return err
	}

	originalCount := len(originalUsernames)

	var usernames []string
	var passwords []string
	var removedPriorWorks []string
	var removedSyntactic []string
	var removedPassOutlier []string
	var removedEmailOutlier []string
	var removedSeqUsers []string
	var removedEmailChains []string
	var removedFod []string
	var removedFor []string
	var removedFBOB []string

	fileStats := config.CleaningStats{}

	if *dryRun {
		// DRY RUN MODE: Count what would be removed without actually removing
		_, _ = cleaning.PriorWorksCleaning(originalUsernames, originalPasswords, breachConfig.ExcessiveEmailThreshold, &removedPriorWorks, &fileStats, *dryRun)
		_, _ = cleaning.RemoveSyntactic(originalUsernames, originalPasswords, &removedSyntactic, &fileStats, TLD_SET)
		_, _ = cleaning.RemoveSeqUsers(originalUsernames, originalPasswords, breachConfig.SequentialUserThreshold, &removedSeqUsers)
		_, _, _ = cleaning.RemoveEmailChains(originalUsernames, originalPasswords, &removedEmailChains, breachConfig.ChainsFile)
		_, _, _ = cleaning.RemoveSuspiciousFollowOnRatios(originalUsernames, originalPasswords, &removedFor, breachConfig.ForCfg)
		_, _ = cleaning.RemoveSuspiciousFollowOnDistribution(originalUsernames, originalPasswords, &removedFod, breachConfig.FodCfg)
		_, _ = cleaning.RemoveFBOB(originalUsernames, originalPasswords, &removedFBOB)

		fileStats.PriorWorkRemovals = len(removedPriorWorks)
		fileStats.SyntacticRemovals = len(removedSyntactic)
		fileStats.Email_SeqUserRemovals = len(removedSeqUsers)
		fileStats.Email_ChainRemovals = len(removedEmailChains)
		fileStats.Pass_ForRemovals = len(removedFor)
		fileStats.Pass_FodRemovals = len(removedFod)
		fileStats.FbobRemovals = len(removedFBOB)
		fileStats.TotalProcessed = originalCount // Use actual cred count

		// Calculate statistical outliers count
		emailOutliersSet := make(map[string]bool)
		for _, cred := range removedSeqUsers {
			emailOutliersSet[cred] = true
		}
		for _, cred := range removedEmailChains {
			emailOutliersSet[cred] = true
		}
		fileStats.EmailOutlierRemovals = len(emailOutliersSet)
		for cred := range emailOutliersSet {
			removedEmailOutlier = append(removedEmailOutlier, cred)
		}

		passOutliersSet := make(map[string]bool)
		for _, cred := range removedFor {
			passOutliersSet[cred] = true
		}
		for _, cred := range removedFod {
			passOutliersSet[cred] = true
		}
		fileStats.PassOutlierRemovals = len(passOutliersSet)
		for cred := range passOutliersSet {
			removedPassOutlier = append(removedPassOutlier, cred)
		}

		// Update global statistics with mutex protection
		statsLock.Lock()
		globalStats.TotalProcessed += fileStats.TotalProcessed
		globalStats.Prior_AsciiRemovals += fileStats.Prior_AsciiRemovals
		globalStats.Prior_LenRemovals += fileStats.Prior_LenRemovals
		globalStats.Prior_HexRemovals += fileStats.Prior_HexRemovals
		globalStats.Prior_InvEmailRemovals += fileStats.Prior_InvEmailRemovals
		globalStats.Prior_ExcEmailRemovals += fileStats.Prior_ExcEmailRemovals
		globalStats.PriorWorkRemovals += fileStats.PriorWorkRemovals
		globalStats.Syn_DupeRemovals += fileStats.Syn_DupeRemovals
		globalStats.Syn_LenEmailRemovals += fileStats.Syn_LenEmailRemovals
		globalStats.Syn_TLDRemovals += fileStats.Syn_TLDRemovals
		globalStats.SyntacticRemovals += fileStats.SyntacticRemovals
		globalStats.EmailOutlierRemovals += fileStats.EmailOutlierRemovals
		globalStats.Email_SeqUserRemovals += fileStats.Email_SeqUserRemovals
		globalStats.Email_ChainRemovals += fileStats.Email_ChainRemovals
		globalStats.PassOutlierRemovals += fileStats.PassOutlierRemovals
		globalStats.Pass_ForRemovals += fileStats.Pass_ForRemovals
		globalStats.Pass_FodRemovals += fileStats.Pass_FodRemovals
		globalStats.FbobRemovals += fileStats.FbobRemovals
		statsLock.Unlock()

		// Write all credentials to destination (nothing removed)
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
		fmt.Printf("Total entries processed: %d\n", fileStats.TotalProcessed)
		fmt.Printf("Prior work checks would remove: %d (%.2f%%)\n",
			fileStats.PriorWorkRemovals,
			percentage(fileStats.PriorWorkRemovals, fileStats.TotalProcessed))
		fmt.Printf("Syntactic checks would remove: %d (%.2f%%)\n",
			fileStats.SyntacticRemovals,
			percentage(fileStats.SyntacticRemovals, fileStats.TotalProcessed))
		fmt.Printf("Email Outlier checks would remove: %d (%.2f%%)\n",
			fileStats.EmailOutlierRemovals,
			percentage(fileStats.EmailOutlierRemovals, fileStats.TotalProcessed))
		fmt.Printf("Password Outlier checks would remove: %d (%.2f%%)\n",
			fileStats.PassOutlierRemovals,
			percentage(fileStats.PassOutlierRemovals, fileStats.TotalProcessed))
		fmt.Printf("FBOB checks would remove: %d (%.2f%%)\n",
			fileStats.FbobRemovals,
			percentage(fileStats.FbobRemovals, fileStats.TotalProcessed))

	} else {
		// ACTUAL REMOVAL MODE: Apply filters independently then take union

		usernames, passwords = cleaning.PriorWorksCleaning(originalUsernames, originalPasswords, breachConfig.ExcessiveEmailThreshold, &removedPriorWorks, &fileStats, *dryRun)
		fileStats.PriorWorkRemovals = len(removedPriorWorks)

		// Path 1: Build set of credentials that survived prior work
		priorWorkSurvivors := make(map[string]bool, len(usernames))
		for i := range usernames {
			priorWorkSurvivors[usernames[i]+":"+passwords[i]] = true
		}

		// Clear original arrays and maps to free memory
		usernames = nil
		passwords = nil

		// Path 2: Apply all other checks to TRUE ORIGINAL data
		otherCheckUsernames := make([]string, len(originalUsernames))
		otherCheckPasswords := make([]string, len(originalPasswords))
		copy(otherCheckUsernames, originalUsernames)
		copy(otherCheckPasswords, originalPasswords)

		otherCheckUsernames, otherCheckPasswords = cleaning.RemoveSyntactic(otherCheckUsernames, otherCheckPasswords, &removedSyntactic, &fileStats, TLD_SET)
		otherCheckUsernames, otherCheckPasswords = cleaning.RemoveSeqUsers(otherCheckUsernames, otherCheckPasswords, breachConfig.SequentialUserThreshold, &removedSeqUsers)
		otherCheckUsernames, otherCheckPasswords, _ = cleaning.RemoveEmailChains(otherCheckUsernames, otherCheckPasswords, &removedEmailChains, breachConfig.ChainsFile)
		otherCheckUsernames, otherCheckPasswords, _ = cleaning.RemoveSuspiciousFollowOnRatios(otherCheckUsernames, otherCheckPasswords, &removedFor, breachConfig.ForCfg)
		otherCheckUsernames, otherCheckPasswords = cleaning.RemoveSuspiciousFollowOnDistribution(otherCheckUsernames, otherCheckPasswords, &removedFod, breachConfig.FodCfg)
		otherCheckUsernames, otherCheckPasswords = cleaning.RemoveFBOB(otherCheckUsernames, otherCheckPasswords, &removedFBOB)

		fileStats.PriorWorkRemovals = len(removedPriorWorks)
		fileStats.SyntacticRemovals = len(removedSyntactic)
		fileStats.Email_SeqUserRemovals = len(removedSeqUsers)
		fileStats.Email_ChainRemovals = len(removedEmailChains)
		fileStats.Pass_ForRemovals = len(removedFor)
		fileStats.Pass_FodRemovals = len(removedFod)
		fileStats.FbobRemovals = len(removedFBOB)
		fileStats.TotalProcessed = originalCount // Use actual cred count

		// Calculate statistical outliers counts
		emailOutliersSet := make(map[string]bool)
		for _, cred := range removedSeqUsers {
			emailOutliersSet[cred] = true
		}
		for _, cred := range removedEmailChains {
			emailOutliersSet[cred] = true
		}
		fileStats.EmailOutlierRemovals = len(emailOutliersSet)
		for cred := range emailOutliersSet {
			removedEmailOutlier = append(removedEmailOutlier, cred)
		}

		passOutliersSet := make(map[string]bool)
		for _, cred := range removedFor {
			passOutliersSet[cred] = true
		}
		for _, cred := range removedFod {
			passOutliersSet[cred] = true
		}
		fileStats.PassOutlierRemovals = len(passOutliersSet)
		for cred := range passOutliersSet {
			removedPassOutlier = append(removedPassOutlier, cred)
		}

		// Take UNION: only keep credentials that survived BOTH paths
		var finalUsernames []string
		var finalPasswords []string
		for i := range otherCheckUsernames {
			credential := otherCheckUsernames[i] + ":" + otherCheckPasswords[i]
			if priorWorkSurvivors[credential] {
				finalUsernames = append(finalUsernames, otherCheckUsernames[i])
				finalPasswords = append(finalPasswords, otherCheckPasswords[i])
			}
		}

		// Clear original arrays and maps to free memory
		priorWorkSurvivors = nil
		otherCheckUsernames = nil
		otherCheckPasswords = nil

		// Update global statistics in removal mode
		statsLock.Lock()
		globalStats.TotalProcessed += fileStats.TotalProcessed
		globalStats.Prior_AsciiRemovals += fileStats.Prior_AsciiRemovals
		globalStats.Prior_LenRemovals += fileStats.Prior_LenRemovals
		globalStats.Prior_HexRemovals += fileStats.Prior_HexRemovals
		globalStats.Prior_InvEmailRemovals += fileStats.Prior_InvEmailRemovals
		globalStats.Prior_ExcEmailRemovals += fileStats.Prior_ExcEmailRemovals
		globalStats.PriorWorkRemovals += fileStats.PriorWorkRemovals
		globalStats.Syn_DupeRemovals += fileStats.Syn_DupeRemovals
		globalStats.Syn_LenEmailRemovals += fileStats.Syn_LenEmailRemovals
		globalStats.Syn_TLDRemovals += fileStats.Syn_TLDRemovals
		globalStats.SyntacticRemovals += fileStats.SyntacticRemovals
		globalStats.EmailOutlierRemovals += fileStats.EmailOutlierRemovals
		globalStats.Email_SeqUserRemovals += fileStats.Email_SeqUserRemovals
		globalStats.Email_ChainRemovals += fileStats.Email_ChainRemovals
		globalStats.PassOutlierRemovals += fileStats.PassOutlierRemovals
		globalStats.Pass_ForRemovals += fileStats.Pass_ForRemovals
		globalStats.Pass_FodRemovals += fileStats.Pass_FodRemovals
		globalStats.FbobRemovals += fileStats.FbobRemovals

		fileRemovals := len(originalUsernames) - len(finalUsernames)
		globalStats.TotalRemovals += fileRemovals
		statsLock.Unlock()

		// Write cleaned credentials to destination (union of both paths)
		outFile, err := os.Create(destPath)
		if err != nil {
			return err
		}
		writer := bufio.NewWriter(outFile)
		for i := range finalUsernames {
			if _, err := writer.WriteString(fmt.Sprintf("%s:%s\n", finalUsernames[i], finalPasswords[i])); err != nil {
				outFile.Close()
				return err
			}
		}
		writer.Flush()
		outFile.Close()

		fmt.Printf("\nProcessed %s: %d entries processed, %d remaining after union\n",
			filepath.Base(srcPath), fileStats.TotalProcessed, len(finalUsernames))
	}

	// Log removed entries
	logFiles := map[string][]string{
		"removed_prior_work.txt":     removedPriorWorks,
		"removed_syntactic.txt":      removedSyntactic,
		"removed_email_outliers.txt": removedEmailOutlier,
		"removed_pass_outliers.txt":  removedPassOutlier,
		"removed_FBOB.txt":           removedFBOB,
	}

	sumf, err := os.OpenFile(filepath.Join(logPath, logSummary), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer sumf.Close()

	// Write file header
	if _, err := sumf.WriteString(fmt.Sprintf("\n=== %s ===\n", filepath.Base(srcPath))); err != nil {
		return err
	}

	for filename, entries := range logFiles {
		if _, err := sumf.WriteString(filename + " contains " + strconv.Itoa(len(entries)) + "\n"); err != nil {
			return err
		}

		logDest := filepath.Join(logPath, filename)
		if err := logRemovals(logDest, entries); err != nil {
			return fmt.Errorf("failed to log removals to %s: %v", filename, err)
		}
	}

	// Suggest GC if this was a large file (>100K credentials)
	if fileStats.TotalProcessed > 100000 {
		runtime.GC()
	}

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

// writeGlobalStats writes the global statistics to the removal summary file
func writeGlobalStats(logPath string) error {
	sumf, err := os.OpenFile(filepath.Join(logPath, logSummary), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer sumf.Close()

	// Write global statistics header
	if _, err := sumf.WriteString("\n\n" + strings.Repeat("=", 60) + "\n"); err != nil {
		return err
	}
	if _, err := sumf.WriteString("GLOBAL REMOVAL STATISTICS\n"); err != nil {
		return err
	}
	if _, err := sumf.WriteString(strings.Repeat("=", 60) + "\n\n"); err != nil {
		return err
	}

	// Write statistics
	stats := []struct {
		name  string
		count int
	}{
		{"Total entries processed", globalStats.TotalProcessed},
		{"Prior work removals", globalStats.PriorWorkRemovals},
		{"Prior work ASCII removals", globalStats.Prior_AsciiRemovals},
		{"Prior work Length removals", globalStats.Prior_LenRemovals},
		{"Prior work Hex Substring removals", globalStats.Prior_HexRemovals},
		{"Prior work Invalid Email removals", globalStats.Prior_InvEmailRemovals},
		{"Prior work Excessive Email removals", globalStats.Prior_ExcEmailRemovals},
		{"Syntactic removals", globalStats.SyntacticRemovals},
		{"Syntactic Duplicates removals", globalStats.Syn_DupeRemovals},
		{"Syntactic Email Length removals", globalStats.Syn_LenEmailRemovals},
		{"Syntactic TLD removals", globalStats.Syn_TLDRemovals},
		{"Email Outlier Removals", globalStats.EmailOutlierRemovals},
		{"Email Outlier Sequential Username removals", globalStats.Email_SeqUserRemovals},
		{"Email Outlier Email chain removals", globalStats.Email_ChainRemovals},
		{"Password Outlier Removals", globalStats.PassOutlierRemovals},
		{"Password Outlier Follow-on distribution removals", globalStats.Pass_FodRemovals},
		{"Password Outlier Follow-on ratio removals", globalStats.Pass_ForRemovals},
		{"FBOB removals", globalStats.FbobRemovals},
	}

	for _, stat := range stats {
		line := fmt.Sprintf("%-40s: %d", stat.name, stat.count)
		if stat.name != "Total entries processed" {
			line += fmt.Sprintf(" (%.2f%%)", percentage(stat.count, globalStats.TotalProcessed))
		}
		line += "\n"
		if _, err := sumf.WriteString(line); err != nil {
			return err
		}
	}

	if _, err := sumf.WriteString("\n"); err != nil {
		return err
	}
	if _, err := sumf.WriteString(fmt.Sprintf("%-40s: %d (%.2f%%)\n",
		"Total removals (all methods)",
		globalStats.TotalRemovals,
		percentage(globalStats.TotalRemovals, globalStats.TotalProcessed))); err != nil {
		return err
	}

	if _, err := sumf.WriteString(fmt.Sprintf("%-40s: %d\n",
		"Remaining entries",
		globalStats.TotalProcessed-globalStats.TotalRemovals)); err != nil {
		return err
	}

	return nil
}

// worker processes files from the jobs channel
func worker(id int, jobs <-chan fileJob, results chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		err := processFile(job.srcPath, job.destPath, job.logPath)
		results <- err
	}
}

// walks through srcDir, and for each file processes it individually.
func main() {
	flag.Parse()

	// Load breach configuration
	var exists bool
	breachConfig, exists = config.GetBreachConfig(*breachName)
	if !exists {
		log.Fatalf("Unknown breach configuration: %s\nAvailable configurations: %v",
			*breachName, config.ListBreachConfigs())
	}

	// Load TLD set
	if err := loadTLDs(breachConfig.TLDFile); err != nil {
		log.Fatalf("Failed to load TLD file %s: %v", breachConfig.TLDFile, err)
	}

	// Set up directories based on config and mode
	sourceDirectory := breachConfig.SrcDirectory
	baseDestDir := breachConfig.DstDirectoryClean

	if *dryRun {
		// For dry-run, use counting destination
		baseDestDir = breachConfig.DstDirectoryCount
	}

	destinationDirectory := filepath.Join(baseDestDir, "data")

	// Allow overriding directories through command line arguments
	args := flag.Args()
	if len(args) > 0 {
		sourceDirectory = args[0]
	}
	if len(args) > 1 {
		baseDestDir = args[1]
		destinationDirectory = filepath.Join(baseDestDir, "data")
	}

	// Create logs directory in the CleanedBreach root
	logsDir := filepath.Join(baseDestDir, "logs")
	if err := os.MkdirAll(logsDir, os.ModePerm); err != nil {
		log.Fatalf("Failed to create logs directory: %v", err)
	}

	if *dryRun {
		fmt.Printf("Running in DRY RUN mode with %d workers - counting what would be removed\n", *workers)
	} else {
		fmt.Printf("Running in REMOVAL mode with %d workers - actually cleaning credentials\n", *workers)
	}

	fmt.Printf("Breach dataset: %s\n", breachConfig.Name)
	fmt.Printf("Source directory: %s\n", sourceDirectory)
	fmt.Printf("Destination directory: %s\n", baseDestDir)
	fmt.Printf("Chains file: %s\n", breachConfig.ChainsFile)

	// PARALLEL MODE for both dry-run and normal mode
	jobs := make(chan fileJob, 100)
	results := make(chan error, 100)
	var wg sync.WaitGroup

	// Start worker goroutines
	for w := 1; w <= *workers; w++ {
		wg.Add(1)
		go worker(w, jobs, results, &wg)
	}

	// Collect all file jobs first
	var allJobs []fileJob
	err := filepath.Walk(sourceDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Determine relative path
		relPath, err := filepath.Rel(sourceDirectory, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(destinationDirectory, relPath)

		// If directory, ensure it exists in destination
		if info.IsDir() {
			return os.MkdirAll(destPath, os.ModePerm)
		}

		// Add file job to queue
		allJobs = append(allJobs, fileJob{
			srcPath:  path,
			destPath: destPath,
			logPath:  logsDir,
		})
		return nil
	})

	if err != nil {
		log.Fatalf("Error collecting files: %v", err)
	}

	// Send jobs to workers
	go func() {
		for _, job := range allJobs {
			jobs <- job
		}
		close(jobs)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	errorCount := 0
	for err := range results {
		if err != nil {
			log.Printf("Error processing file: %v", err)
			errorCount++
		}
	}

	if errorCount > 0 {
		log.Fatalf("Completed with %d errors", errorCount)
	}

	// Write global statistics to the removal summary file
	if err := writeGlobalStats(logsDir); err != nil {
		log.Fatalf("Error writing global statistics: %v", err)
	}

	fmt.Println("\nProcessing complete.")

	// Also print to console
	fmt.Println("\n=== GLOBAL STATISTICS ===")
	fmt.Printf("Total entries processed: %d\n", globalStats.TotalProcessed)
	fmt.Printf("Prior work checks %s: %d (%.2f%%)\n",
		map[bool]string{true: "would remove", false: "removed"}[*dryRun],
		globalStats.PriorWorkRemovals,
		percentage(globalStats.PriorWorkRemovals, globalStats.TotalProcessed))
	fmt.Printf("Syntactic checks %s: %d (%.2f%%)\n",
		map[bool]string{true: "would remove", false: "removed"}[*dryRun],
		globalStats.SyntacticRemovals,
		percentage(globalStats.SyntacticRemovals, globalStats.TotalProcessed))
	fmt.Printf("Email Outlier checks %s: %d (%.2f%%)\n",
		map[bool]string{true: "would remove", false: "removed"}[*dryRun],
		globalStats.EmailOutlierRemovals,
		percentage(globalStats.EmailOutlierRemovals, globalStats.TotalProcessed))
	fmt.Printf("Password Outlier checks %s: %d (%.2f%%)\n",
		map[bool]string{true: "would remove", false: "removed"}[*dryRun],
		globalStats.PassOutlierRemovals,
		percentage(globalStats.PassOutlierRemovals, globalStats.TotalProcessed))
	fmt.Printf("FBOB checks %s: %d (%.2f%%)\n",
		map[bool]string{true: "would remove", false: "removed"}[*dryRun],
		globalStats.FbobRemovals,
		percentage(globalStats.FbobRemovals, globalStats.TotalProcessed))

	if !*dryRun {
		fmt.Printf("Total removals (union of all filters): %d (%.2f%%)\n",
			globalStats.TotalRemovals,
			percentage(globalStats.TotalRemovals, globalStats.TotalProcessed))
		fmt.Printf("Remaining entries: %d\n", globalStats.TotalProcessed-globalStats.TotalRemovals)
	}
}

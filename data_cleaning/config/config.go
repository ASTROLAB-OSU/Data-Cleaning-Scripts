package config

// CleaningStats stores counts of what would be removed by each method
type CleaningStats struct {
	PriorWorkRemovals       int
	Prior_AsciiRemovals     int
	Prior_LenRemovals       int
	Prior_HexRemovals       int
	Prior_InvEmailRemovals  int
	Prior_ExcEmailRemovals  int
	RuleBasedRemovals       int
	Rule_SeqUserRemovals    int
	Rule_DupeRemovals       int
	Rule_LenEmailRemovals   int
	Rule_TLDRemovals        int
	SuspiciousEmailRemovals int
	FodRemovals             int
	ForRemovals             int
	FbobRemovals            int
	TotalRemovals           int
	TotalProcessed          int
}

// BreachConfig holds configuration for processing a specific breach dataset
type BreachConfig struct {
	Name                    string
	SrcDirectory            string
	DstDirectoryClean       string
	DstDirectoryCount       string
	ChainsFile              string
	ForCfg                  string
	FodCfg                  string
	TLDFile                 string
	ExcessiveEmailThreshold int
}

// Predefined breach configurations
var BreachConfigs = map[string]BreachConfig{
	"4iq": {
		Name:                    "4iq",
		SrcDirectory:            "/data/credential-linking/BreachCompilation/data",
		DstDirectoryClean:       "/data/lucas/4iq_cleaned",
		DstDirectoryCount:       "/data/lucas/4iq_counted",
		ChainsFile:              "/home/lucas/Data-Cleaning/comb-cleaning/scripts/data_cleaning/config/4iq_suspicious_chains.csv",
		ForCfg:                  "/home/lucas/Data-Cleaning/comb-cleaning/scripts/data_cleaning/config/4iq_for_passwords.json",
		FodCfg:                  "/home/lucas/Data-Cleaning/comb-cleaning/scripts/data_cleaning/config/4iq_fod_passwords.json",
		TLDFile:                 "/home/lucas/Data-Cleaning/comb-cleaning/scripts/data_cleaning/config/iana_tlds.txt",
		ExcessiveEmailThreshold: 100,
	},
	"comb": {
		Name:                    "comb",
		SrcDirectory:            "/data/credential-linking/COMB/CompilationOfManyBreaches/data",
		DstDirectoryClean:       "/data/lucas/comb_cleaned",
		DstDirectoryCount:       "/data/lucas/comb_counted",
		ChainsFile:              "/home/lucas/Data-Cleaning/comb-cleaning/scripts/data_cleaning/config/comb_suspicious_chains.csv",
		ForCfg:                  "/home/lucas/Data-Cleaning/comb-cleaning/scripts/data_cleaning/config/comb_for_passwords.json",
		FodCfg:                  "/home/lucas/Data-Cleaning/comb-cleaning/scripts/data_cleaning/config/comb_fod_passwords.json",
		TLDFile:                 "/home/lucas/Data-Cleaning/comb-cleaning/scripts/data_cleaning/config/iana_tlds.txt",
		ExcessiveEmailThreshold: 100,
	},
}

// GetBreachConfig returns the configuration for a specific breach
func GetBreachConfig(breachName string) (BreachConfig, bool) {
	cfg, exists := BreachConfigs[breachName]
	return cfg, exists
}

// ListBreachConfigs returns all available breach configuration names
func ListBreachConfigs() []string {
	names := make([]string, 0, len(BreachConfigs))
	for name := range BreachConfigs {
		names = append(names, name)
	}
	return names
}

package config

// CleaningStats stores counts of what would be removed by each method
type CleaningStats struct {
	PriorWorkRemovals      int
	Prior_AsciiRemovals    int
	Prior_LenRemovals      int
	Prior_HexRemovals      int
	Prior_InvEmailRemovals int
	Prior_ExcEmailRemovals int
	SyntacticRemovals      int
	Syn_DupeRemovals       int
	Syn_LenEmailRemovals   int
	Syn_TLDRemovals        int
	PassOutlierRemovals    int
	EmailOutlierRemovals   int
	Email_SeqUserRemovals  int
	Email_ChainRemovals    int
	Pass_FodRemovals       int
	Pass_ForRemovals       int
	FbobRemovals           int
	TotalRemovals          int
	TotalProcessed         int
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
	SequentialUserThreshold int
}

// Predefined breach configurations
var BreachConfigs = map[string]BreachConfig{
	"4iq": {
		Name:                    "4iq",
		SrcDirectory:            "[Insert Config]",
		DstDirectoryClean:       "[Insert Config]",
		DstDirectoryCount:       "[Insert Config]",
		ChainsFile:              "[Insert Config]",
		ForCfg:                  "[Insert Config]",
		FodCfg:                  "[Insert Config]",
		TLDFile:                 "[Insert Config]",
		ExcessiveEmailThreshold: 100,
		SequentialUserThreshold: 100,
	},
	"comb": {
		Name:                    "comb",
		SrcDirectory:            "[Insert Config]",
		DstDirectoryClean:       "[Insert Config]",
		DstDirectoryCount:       "[Insert Config]",
		ChainsFile:              "[Insert Config]",
		ForCfg:                  "[Insert Config]",
		FodCfg:                  "[Insert Config]",
		TLDFile:                 "[Insert Config]",
		ExcessiveEmailThreshold: 100,
		SequentialUserThreshold: 100,
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

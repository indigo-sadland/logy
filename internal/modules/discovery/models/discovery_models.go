package models

type Config struct {
	ToolConfig map[string]ToolConfig
	Logf       func(string, ...any)
}

type ToolConfig struct {
	ResolversFile string
	ConfigFile    string
	WordlistFile  string
	APIKey        string
	BaseURL       string
}

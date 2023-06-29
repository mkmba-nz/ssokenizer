package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/superfly/ssokenizer"
	"github.com/superfly/ssokenizer/google"
	"gopkg.in/yaml.v3"
)

var (
	Version string
	Commit  string
)

func main() {
	if err := Run(context.Background(), os.Args[1:]); err == flag.ErrHelp {
		os.Exit(2)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		os.Exit(1)
	}
}

// Run is the main entry into the binary execution.
func Run(ctx context.Context, args []string) error {
	fmt.Println(VersionString())

	// Extract command name.
	var cmd string
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	switch cmd {
	case "serve":
		return NewServeCommand().Run(args)
	case "version":
		fmt.Println(VersionString())
		return nil

	default:
		if cmd == "" || cmd == "help" || strings.HasPrefix(cmd, "-") {
			printUsage()
			return flag.ErrHelp
		}
		return fmt.Errorf("ssokenizer %s: unknown command", cmd)
	}
}

type Config struct {
	// tokenizer seal (public) key
	SealKey string `yaml:"seal_key"`

	// auth key to put on tokenizer secrets
	RelyingPartyAuth string `yaml:"relying_party_auth"`

	// allowed rp urls to return user to after auth dance
	ReturnTo []string `yaml:"return_to"`

	Log               LogConfig                         `yaml:"log"`
	HTTP              HTTPConfig                        `yaml:"http"`
	IdentityProviders map[string]IdentityProviderConfig `yaml:"identity_providers"`
}

// NewConfig returns a new instance of Config with defaults set.
func NewConfig() Config {
	var config Config
	return config
}

// Validate returns an error if the config is invalid.
func (c *Config) Validate() error {
	if c.RelyingPartyAuth == "" {
		return errors.New("missing relying_party_auth")
	}
	if c.SealKey == "" {
		return errors.New("missing seal_key")
	}
	if len(c.ReturnTo) == 0 {
		return errors.New("missing return_to")
	}
	if c.HTTP.Address == "" {
		return errors.New("missing http.address")
	}
	if c.HTTP.URL == "" {
		return errors.New("missing http.url")
	}
	return nil
}

type LogConfig struct {
	Debug bool `yaml:"debug"`
}

type HTTPConfig struct {
	// address for http server to listen on
	Address string `yaml:"address"`

	// url that ssokenizer can be reached at
	URL string `yaml:"url"`
}

type IdentityProviderConfig struct {
	// idb profile name (e.g. google)
	Profile string `yaml:"profile"`

	// oauth client ID
	ClientID string `yaml:"client_id"`

	// oauth client secret
	ClientSecret string `yaml:"client_secret"`

	// oauth scopes to request
	Scopes []string `yaml:"scopes"`
}

func (c IdentityProviderConfig) providerConfig(baseURL string) (ssokenizer.ProviderConfig, error) {
	switch c.Profile {
	case "google":
		return google.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			RedirectURL:  baseURL + "/callback",
			RefreshURL:   baseURL + "/refresh",
		}, nil
	default:
		return nil, fmt.Errorf("unknown identity provider profile: %s", c.Profile)
	}
}

// UnmarshalConfig unmarshals config from data. Expands variables as needed.
func UnmarshalConfig(config *Config, data []byte) error {
	// Expand environment variables.
	data = []byte(os.ExpandEnv(string(data)))

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // strict checking
	return dec.Decode(&config)
}

func VersionString() string {
	// Print version & commit information, if available.
	if Version != "" {
		return fmt.Sprintf("ssokenizer %s, commit=%s", Version, Commit)
	} else if Commit != "" {
		return fmt.Sprintf("ssokenizer commit=%s", Commit)
	}
	return "ssokenizer development build"
}

// printUsage prints the help screen to STDOUT.
func printUsage() {
	fmt.Println(`
ssokenizer is a SSO service.

Usage:

	ssokenizer <command> [arguments]

The commands are:

	serve        runs the server
	version      prints the version
`[1:])
}

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ftauth/ftauth/pkg/jwt"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

// ServerConfig holds configuration variables for the server.
type ServerConfig struct {
	Scheme string
	Host   string
	Port   string
}

// URL returns the main gateway URL for the server.
func (s *ServerConfig) URL() string {
	host := s.Host
	includePort := func() bool {
		if s.Port == "" {
			return false
		}
		if s.Scheme == "http" {
			return s.Port != "80"
		}
		// s.Scheme == "https"
		return s.Port != "443"
	}()
	if includePort {
		host = fmt.Sprintf("%s:%s", host, s.Port)
	}
	uri := url.URL{
		Scheme: s.Scheme,
		Host:   host,
	}
	return uri.String()
}

// DatabaseConfig holds configuration variables for the database.
type DatabaseConfig struct {
	URL      string
	APIKey   string
	Username string
	Password string

	// For embedded DB
	Dir string // Path to store data in (for embedded)
}

// TokenConfig holds settings for each JWT signing token.
type TokenConfig struct {
	PrivateKey *jwt.Key
	PublicKey  *jwt.Key
}

// OAuthConfig holds configuration variables for FTAuth
type OAuthConfig struct {
	Admin struct {
		ClientID string // can be assigned or randomly generated
		Username string
		Password string
	}
	Tokens struct {
		PrivateKeyFile   string
		DefaultAlgorithm jwt.Algorithm
		KeySet           map[jwt.Algorithm]TokenConfig
	}
	Scopes struct {
		Default string
	}
	Authentication struct {
		ROPC bool
	}
	Template struct {
		Options *templateOptions
	}
}

type templateOptions struct {
	Dir          string // Local path to template files
	PrimaryColor string // Hex value of primary color
	Name         string
}

// Config holds configuration information for the program.
type Config struct {
	Server   *ServerConfig
	Database *DatabaseConfig
	OAuth    *OAuthConfig
	Remain   map[string]interface{} `mapstructure:",remain"`
}

var (
	// Current is the current configuration for the server.
	Current Config

	configPath string
)

func setConfigDefaults() {
	viper.SetDefault("server", map[string]interface{}{
		"scheme": "http",
		"host":   "localhost",
		"port":   "8000",
	})

	viper.SetDefault("database", map[string]interface{}{
		"url": "http://localhost:8080/graphql",
	})

	viper.SetDefault("oauth.admin", map[string]interface{}{
		"clientID": "",
		"username": "admin",
		"password": "password",
	})

	viper.SetDefault("oauth.scopes.default", "default")
	viper.SetDefault("oauth.authentication.ropc", false)
	viper.SetDefault("oauth.template.options", map[string]interface{}{
		"dir":          "web/template",
		"primaryColor": "#4d87ca",
		"name":         "Demo",
	})
	viper.SetDefault("oauth.tokens.defaultAlgorithm", string(jwt.AlgorithmRSASHA256))
}

// LoadConfig loads the config file from disk.
func LoadConfig() {
	viper.AddConfigPath("/etc/ftauth/")
	viper.AddConfigPath("$HOME/.ftauth")
	// viper.AddConfigPath(".")

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	setConfigDefaults()

	viper.SetEnvPrefix("ftauth")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("No configuration found. Running with defaults...")
			configPath, err = getConfigurationDirectory()
			if err != nil {
				panic(err)
			}
		} else {
			panic(fmt.Errorf("Unable to read config file: %v", err))
		}
	} else {
		configPath = viper.ConfigFileUsed()
	}

	err = viper.Unmarshal(&Current)
	if err != nil {
		panic(fmt.Errorf("Error unmarshalling config: %v", err))
	}

	Current.OAuth.Tokens.KeySet = make(map[jwt.Algorithm]TokenConfig)

	// Set paths with known configPath
	if Current.OAuth.Tokens.PrivateKeyFile == "" {
		Current.OAuth.Tokens.PrivateKeyFile = filepath.Join(configPath, "jwks.json")
	}
	if Current.Database.Dir == "" {
		Current.Database.Dir = filepath.Join(configPath, "data")
	}

	if _, err := os.Stat(Current.OAuth.Tokens.PrivateKeyFile); os.IsNotExist(err) {
		generatePrivateKeys()
		savePrivateKeys(Current.OAuth.Tokens.PrivateKeyFile)
	} else {
		loadPrivateKeys()
	}
}

func getConfigurationDirectory() (string, error) {
	var configDir string

	// Prefer /etc
	configDir = "/etc/ftauth"
	if _, err := os.Stat(configDir); err == nil {
		return configDir, nil
	} else if os.IsNotExist(err) {
		// Try to create /etc/ftauth
		// For non-sudo users, this is not possible
		if err := os.Mkdir(configDir, 0770); err == nil {
			return configDir, nil
		}
	} else {
		return "", err
	}

	// Check home directory
	home, err := homedir.Dir()
	if err != nil {
		log.Fatalf("Could not retrieve home directory: %v", err)
	}
	configDir = filepath.Join(home, ".ftauth")
	if _, err := os.Stat(configDir); err == nil {
		return configDir, nil
	} else if os.IsNotExist(err) {
		if err := os.Mkdir(configDir, 0777); err == nil {
			return configDir, nil
		}
	} else {
		return "", err
	}

	return "", errors.New("could not locate viable storage dir")
}

func loadPrivateKeys() {
	// Read and parse server's public/private key pair
	b, err := ioutil.ReadFile(Current.OAuth.Tokens.PrivateKeyFile)
	if err != nil {
		panic(fmt.Errorf("Error reading private key file: %v", err))
	}

	jwks, err := jwt.DecodeKeySet(string(b))
	if err != nil {
		panic(fmt.Errorf("Error decoding private key file: %v", err))
	}

	for _, key := range jwks.Keys {
		alg := key.Algorithm
		Current.OAuth.Tokens.KeySet[alg] = TokenConfig{
			PrivateKey: key,
			PublicKey:  key.PublicJWK(),
		}
	}
}

// generatePrivateKeys generates RSA and EC keys to support various clients and use cases.
func generatePrivateKeys() {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		panic(err)
	}

	for _, alg := range []jwt.Algorithm{jwt.AlgorithmRSASHA256, jwt.AlgorithmPSSSHA256} {
		privateJWK, err := jwt.NewJWKFromRSAPrivateKey(rsaKey, alg)
		if err != nil {
			panic(err)
		}
		publicJWK := privateJWK.PublicJWK()
		Current.OAuth.Tokens.KeySet[alg] = TokenConfig{
			PrivateKey: privateJWK,
			PublicKey:  publicJWK,
		}
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	privateJWK, err := jwt.NewJWKFromECDSAPrivateKey(ecdsaKey)
	if err != nil {
		panic(err)
	}
	publicJWK := privateJWK.PublicJWK()

	Current.OAuth.Tokens.KeySet[jwt.AlgorithmECDSASHA256] = TokenConfig{
		PrivateKey: privateJWK,
		PublicKey:  publicJWK,
	}
}

// Saves the private keys as a JWKS to filename.
func savePrivateKeys(filename string) {
	jwks := Current.JWKS(true)

	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0700)
	if err != nil {
		panic(fmt.Errorf("Error opening file: %v", err))
	}
	defer file.Close()

	err = json.NewEncoder(file).Encode(jwks)
	if err != nil {
		panic(fmt.Errorf("Error writing file: %v", err))
	}
}

// JWKS returns the config's JSON Web Key Set.
func (config Config) JWKS(private bool) *jwt.KeySet {
	var keys []*jwt.Key
	for _, conf := range config.OAuth.Tokens.KeySet {
		if private {
			keys = append(keys, conf.PrivateKey)
		} else {
			keys = append(keys, conf.PublicKey)
		}
	}
	return &jwt.KeySet{Keys: keys}
}

// GetKeyForAlgorithm returns a cached key for the algorithm.
func (config Config) GetKeyForAlgorithm(alg jwt.Algorithm, private bool) (*jwt.Key, error) {
	if conf, ok := config.OAuth.Tokens.KeySet[alg]; ok {
		if private {
			return conf.PrivateKey, nil
		}
		return conf.PublicKey, nil
	}
	return nil, errors.New("key not found for algorithm")
}

// DefaultSigningKey returns the server's default key used for token signing.
func (config Config) DefaultSigningKey() *jwt.Key {
	key, _ := config.GetKeyForAlgorithm(config.OAuth.Tokens.DefaultAlgorithm, true)
	return key
}

// DefaultVerificationKey returns the server's default key used for token verifications.
func (config Config) DefaultVerificationKey() *jwt.Key {
	key, _ := config.GetKeyForAlgorithm(config.OAuth.Tokens.DefaultAlgorithm, false)
	return key
}

// SupportedAlgorithms returns a list of all supported signing algorithms.
func (config *Config) SupportedAlgorithms() []jwt.Algorithm {
	var algorithms []jwt.Algorithm
	for alg := range config.OAuth.Tokens.KeySet {
		algorithms = append(algorithms, alg)
	}
	return algorithms
}

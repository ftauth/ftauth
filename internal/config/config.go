package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"github.com/ftauth/ftauth/jwt"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

// ServerConfig holds configuration variables for the server.
type ServerConfig struct {
	Scheme string
	Host   string
	Port   int
}

// URL returns the main gateway URL for the server.
func (s *ServerConfig) URL() string {
	host := s.Host
	if s.Port > 0 {
		host = fmt.Sprintf("%s:%d", host, s.Port)
	}
	uri := url.URL{
		Scheme: s.Scheme,
		Host:   host,
	}
	return uri.String()
}

// DatabaseConfig holds configuration variables for the database.
type DatabaseConfig struct {
	Host   string
	Port   int
	DBName string
	Dir    string // Path to store data in
}

// OAuthConfig holds configuration variables for FTOAuth
type OAuthConfig struct {
	Tokens struct {
		PrivateKeyFile string
		PublicKey      *jwt.Key
		PrivateKey     *jwt.Key
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
	viper.SetDefault("server", &ServerConfig{
		Scheme: "http",
		Host:   "localhost",
		Port:   8000,
	})

	viper.SetDefault("database", &DatabaseConfig{
		Host:   "localhost",
		Port:   5432,
		DBName: "oauth",
	})

	viper.SetDefault("oauth.scopes.default", "default")
	viper.SetDefault("oauth.authentication.ropc", false)
	viper.SetDefault("oauth.template.options", &templateOptions{
		Dir:          "template",
		PrimaryColor: "#4d87ca",
	})
}

// LoadConfig loads the config file from disk.
func LoadConfig() {
	viper.AddConfigPath("/etc/ftauth/")
	viper.AddConfigPath("$HOME/.ftauth")
	// viper.AddConfigPath(".")

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	setConfigDefaults()

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

	// Set paths with known configPath
	if Current.OAuth.Tokens.PrivateKeyFile == "" {
		Current.OAuth.Tokens.PrivateKeyFile = filepath.Join(configPath, "private.pem")
	}
	if Current.Database.Dir == "" {
		Current.Database.Dir = filepath.Join(configPath, "data")
	}

	if _, err := os.Stat(Current.OAuth.Tokens.PrivateKeyFile); os.IsNotExist(err) {
		generatePrivateKey()
	} else {
		loadPrivateKey()
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

func loadPrivateKey() {
	// Read and parse server's public/private key pair
	b, err := ioutil.ReadFile(Current.OAuth.Tokens.PrivateKeyFile)
	if err != nil {
		panic(fmt.Errorf("Error reading private key file: %v", err))
	}

	p, _ := pem.Decode(b)
	if p == nil {
		panic(fmt.Errorf("Error reading private key file"))
	}

	key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		panic(fmt.Errorf("Error parsing private key: %v", err))
	}

	Current.OAuth.Tokens.PrivateKey, err = jwt.NewJWKFromRSAPrivateKey(key)
	if err != nil {
		panic(err)
	}
	Current.OAuth.Tokens.PublicKey, err = jwt.NewJWKFromRSAPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
}

func generatePrivateKey() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	privateKeyFile := Current.OAuth.Tokens.PrivateKeyFile
	file, err := os.Create(privateKeyFile)
	if err != nil {
		panic(err)
	}

	// Encode PEM and write to disk
	b := x509.MarshalPKCS1PrivateKey(privateKey)

	err = pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: b,
	})
	if err != nil {
		panic(err)
	}

	Current.OAuth.Tokens.PrivateKey, err = jwt.NewJWKFromRSAPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}

	Current.OAuth.Tokens.PublicKey, err = jwt.NewJWKFromRSAPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
}

package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/dnys1/ftoauth/jwt"
	"github.com/spf13/viper"
)

// ServerConfig holds configuration variables for the server.
type ServerConfig struct {
	Scheme string
	Host   string
	Port   string
}

// DatabaseConfig holds configuration variables for the database.
type DatabaseConfig struct {
	Host   string
	Port   string
	DBName string
}

// OAuthConfig holds configuration variables for FTOAuth
type OAuthConfig struct {
	Tokens struct {
		PublicKeyFile  string
		PrivateKeyFile string
		PublicKey      *jwt.Key
		PrivateKey     *jwt.Key
	}
	Scopes struct {
		Default string
	}
	Authentication struct {
		ROPC     bool
		Template struct {
			Login struct {
				Enabled bool
				Path    string
			}
			Register struct {
				Enabled bool
				Path    string
			}
			Options struct {
				PrimaryColor string
			}
		}
	}
}

// Config holds configuration information for the program.
type Config struct {
	Server   *ServerConfig
	Database *DatabaseConfig
	OAuth    *OAuthConfig
	Remain   map[string]interface{} `mapstructure:",remain"`
}

// Current is the current configuration for the server.
var Current Config

// LoadConfig loads the config file from disk.
func LoadConfig() {
	viper.AddConfigPath("/etc/ftoauth/")
	viper.AddConfigPath(".")

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// ignore
		} else {
			panic(fmt.Errorf("Unable to read config file: %v", err))
		}
	}

	err = viper.Unmarshal(&Current)
	if err != nil {
		panic(fmt.Errorf("Error unmarshalling config: %v", err))
	}

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

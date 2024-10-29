package config

import (
	"fmt"

	"github.com/caarlos0/env/v9"
	"github.com/joho/godotenv"
)

type DatabaseConfig struct {
	DBUser     string `env:"DB_USER,required"`
	DBPassword string `env:"DB_PASSWORD,required"`
	DBHost     string `env:"DB_HOST"              envDefault:"localhost"`
	DBPort     int    `env:"DB_PORT"              envDefault:"3306"`
	DBName     string `env:"DB_NAME,required"`
}

type OAuthConfig struct {
	GithubClientID       string `env:"GITHUB_CLIENT_ID,required"`
	GithubClientSecret   string `env:"GITHUB_CLIENT_SECRET,required"`
	GoogleClientID       string `env:"GOOGLE_CLIENT_ID,required"`
	GoogleClientSecret   string `env:"GOOGLE_CLIENT_SECRET,required"`
	FacebookClientID     string `env:"FACEBOOK_CLIENT_ID,required"`
	FacebookClientSecret string `env:"FACEBOOK_CLIENT_SECRET,required"`
}

type Config struct {
	Database     DatabaseConfig
	OAuth        OAuthConfig
	JWTSecretKey []byte
	AccessTokens map[string][]byte
}

type UserSession struct {
	UserID       string
	AuthMethod   string
	AccessToken  string
	RefreshToken string
	ClientID     string
}

func LoadConfig() (*Config, error) {
	// Load .env or .secrets file
	if err := godotenv.Load("tests/.secrets"); err != nil {
		return nil, fmt.Errorf("error loading .secrets file: %w", err)
	}

	cfg := &Config{
		Database:     DatabaseConfig{},
		OAuth:        OAuthConfig{},
		AccessTokens: make(map[string][]byte),
	}

	if err := env.Parse(&cfg.Database); err != nil {
		return nil, fmt.Errorf("failed to parse database environment variables: %w", err)
	}

	if err := env.Parse(&cfg.OAuth); err != nil {
		return nil, fmt.Errorf("failed to parse OAuth environment variables: %w", err)
	}

	// Parse JWTSecretKey as string and convert to []byte
	var jwtSecretKey struct {
		Key string `env:"JWT_SECRET_KEY,required"`
	}

	if err := env.Parse(&jwtSecretKey); err != nil {
		return nil, fmt.Errorf("failed to parse JWT secret key: %w", err)
	}

	cfg.JWTSecretKey = []byte(jwtSecretKey.Key)

	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config environment variables: %w", err)
	}

	return cfg, nil
}

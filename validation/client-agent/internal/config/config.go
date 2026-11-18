// Package config loads client-agent runtime settings.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type Config struct {
	Listen             string
	GatewayAddress     string
	ServerName         string
	InsecureSkipVerify bool
	AllowedOrigins     []string
}

type fileConfig struct {
	Listen             string   `json:"listen"`
	GatewayAddress     string   `json:"gateway_address"`
	ServerName         string   `json:"server_name"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	AllowedOrigins     []string `json:"allowed_origins"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var raw fileConfig
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("parse config: multiple JSON values")
		}
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if raw.Listen == "" || raw.GatewayAddress == "" || raw.ServerName == "" {
		return Config{}, errors.New("listen, gateway_address, and server_name are required")
	}
	if len(raw.AllowedOrigins) == 0 {
		raw.AllowedOrigins = []string{"http://127.0.0.1:5173", "http://localhost:5173"}
	}
	return Config{
		Listen:             raw.Listen,
		GatewayAddress:     raw.GatewayAddress,
		ServerName:         raw.ServerName,
		InsecureSkipVerify: raw.InsecureSkipVerify,
		AllowedOrigins:     raw.AllowedOrigins,
	}, nil
}

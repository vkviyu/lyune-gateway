package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-agent.json")
	if err := os.WriteFile(path, []byte(`{
		"listen": "127.0.0.1:8787",
		"gateway_address": "gateway.example.com:8443",
		"server_name": "gateway.example.com",
		"insecure_skip_verify": false,
		"allowed_origins": ["http://localhost:5173"]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Listen != "127.0.0.1:8787" ||
		config.GatewayAddress != "gateway.example.com:8443" ||
		config.ServerName != "gateway.example.com" ||
		config.InsecureSkipVerify ||
		len(config.AllowedOrigins) != 1 {
		t.Fatalf("unexpected config: %+v", config)
	}
}

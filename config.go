package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	Server struct {
		Address string `json:"address"`
	} `json:"server"`
	DataDir string `json:"data_dir"`
	TLS     struct {
		Enabled  bool   `json:"enabled"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	} `json:"tls"`
	Redis struct {
		Host     string `json:"host"`
		Port     string `json:"port"`
		Password string `json:"password"`
		DB       int    `json:"db"`
	} `json:"redis"`
	Security struct {
		JWTSecret    string `json:"jwt_secret"`
		UserStoreKey string `json:"user_store_key"`
	} `json:"security"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

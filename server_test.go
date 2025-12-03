package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func getTestConfig(t *testing.T) *Config {
	tmpDir, err := os.MkdirTemp("", "gotraining-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	c := &Config{}
	c.Server.Address = ":8080"
	c.DataDir = tmpDir
	c.Security.JWTSecret = "test-secret"
	c.Security.UserStoreKey = "test-key-must-be-32-bytes-long-!!"
	c.TLS.Enabled = false
	c.Redis.Host = "localhost"
	c.Redis.Port = "6379"
	c.Redis.Password = ""
	c.Redis.DB = 0
	return c
}

func TestNewServer(t *testing.T) {
	config := getTestConfig(t)
	config.Server.Address = ":9090"

	s, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if s.config.Server.Address != ":9090" {
		t.Errorf("expected addr :9090, got %s", s.config.Server.Address)
	}
}

func TestHandleHome(t *testing.T) {
	s, err := NewServer(getTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.handleHome)

	handler.ServeHTTP(rr, req)

	// Home page now serves index.html, so we check for HTML content
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check that response contains HTML content
	if !strings.Contains(rr.Body.String(), "<!DOCTYPE html>") && !strings.Contains(rr.Body.String(), "Dark Angel") {
		t.Errorf("handler did not return HTML content: got %v", rr.Body.String())
	}
}

func TestHandleHello(t *testing.T) {
	s, err := NewServer(getTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		queryParams  string
		expectedBody string
	}{
		{
			name:         "Without name param",
			queryParams:  "",
			expectedBody: "Hello, World!\n",
		},
		{
			name:         "With name param",
			queryParams:  "?name=Gopher",
			expectedBody: "Hello, Gopher!\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/hello"+tt.queryParams, nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(s.handleHello)

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, http.StatusOK)
			}

			if rr.Body.String() != tt.expectedBody {
				t.Errorf("handler returned unexpected body: got %v want %v",
					rr.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestHandleHealth(t *testing.T) {
	s, err := NewServer(getTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.handleHealth)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "OK\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestHandleEndCmd(t *testing.T) {
	s, err := NewServer(getTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}

	// Test without query param (should not shutdown)
	req, err := http.NewRequest("GET", "/EndCmd", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.handleEndCmd)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "EndCmd endpoint - use ?darkangel to shutdown\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestHandleEndCmd_Shutdown(t *testing.T) {
	// Note: We cannot easily test os.Exit(0) in a unit test without mocking os.Exit or running in a subprocess.
	// For this unit test, we will just verify the response message, assuming the goroutine for os.Exit triggers.
	// To properly test os.Exit, we would need a more complex setup which might be overkill here.

	s, err := NewServer(getTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "/EndCmd?darkangel=true", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.handleEndCmd)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check if response contains "shutting down"
	if !strings.Contains(rr.Body.String(), "shutting down") {
		t.Errorf("handler returned unexpected body: got %v", rr.Body.String())
	}

	// Verify that the shutdown signal was sent
	select {
	case <-s.shutdownCh:
		// Success: channel is closed or received value
	case <-time.After(1 * time.Second):
		t.Error("shutdown channel was not closed")
	}
}

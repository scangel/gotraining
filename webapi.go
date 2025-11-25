package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

const (
	defaultName    = "World"
	queryParamName = "name"
	queryParamKey  = "darkangel"

	pathHome      = "/"
	pathHello     = "/hello"
	pathHealth    = "/health"
	pathEndCmd    = "/EndCmd"
	pathLogin     = "/login"
	pathWellKnown = "/.well-known/openid-configuration"
	pathToken     = "/oauth/token"
	pathUserInfo  = "/oauth/userinfo"
	pathRegister  = "/oauth/register"
	pathAuthorize = "/oauth/authorize"
)

func (s *Server) routes() {
	// Serve static files
	fs := http.FileServer(http.Dir("./static"))
	s.mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Basic routes
	s.mux.HandleFunc(pathHome, s.handleHome)
	s.mux.HandleFunc(pathHello, s.handleHello)
	s.mux.HandleFunc(pathHealth, s.handleHealth)
	s.mux.HandleFunc(pathEndCmd, s.handleEndCmd)
	s.mux.HandleFunc(pathLogin, s.handleLogin)
	s.mux.HandleFunc("/logout", s.handleLogout)

	// OAuth/OIDC routes
	s.mux.HandleFunc(pathWellKnown, s.handleWellKnown)
	s.mux.HandleFunc(pathToken, s.handleToken)
	s.mux.HandleFunc(pathUserInfo, s.handleUserInfo)
	s.mux.HandleFunc(pathRegister, s.handleRegister)
	s.mux.HandleFunc(pathAuthorize, s.handleAuthorize)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to Go HTTP Server!\n")
}

func (s *Server) handleHello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get(queryParamName)
	if name == "" {
		name = defaultName
	}
	fmt.Fprintf(w, "Hello, %s!\n", name)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/login.html")
}

func (s *Server) handleEndCmd(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has(queryParamKey) {
		log.Println("Shutdown command received via API")
		fmt.Fprintf(w, "Server is shutting down...\n")

		go func() {
			time.Sleep(100 * time.Millisecond)
			close(s.shutdownCh)
		}()
		return
	}

	fmt.Fprintf(w, "EndCmd endpoint - use ?%s to shutdown\n", queryParamKey)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "No active session", http.StatusBadRequest)
		return
	}

	// Delete session from Redis
	if err := s.sessionStore.DeleteSession(cookie.Value); err != nil {
		log.Printf("Failed to delete session: %v", err)
	}

	// Clear the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}

func (s *Server) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + pathAuthorize,
		"token_endpoint":                        issuer + pathToken,
		"userinfo_endpoint":                     issuer + pathUserInfo,
		"registration_endpoint":                 issuer + pathRegister,
		"jwks_uri":                              issuer + "/oauth/jwks",
		"response_types_supported":              []string{"code", "token", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"HS512"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "roles"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if grantType != "password" {
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
		return
	}

	user, err := s.authService.Authenticate(username, password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	idToken, err := s.authService.GenerateIDToken(user)
	if err != nil {
		http.Error(w, "Failed to generate ID token", http.StatusInternalServerError)
		return
	}

	accessToken, err := s.authService.GenerateAccessToken(user)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Create session in Redis
	sessionID, err := s.sessionStore.CreateSession(user.ID, 0)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie (HTTP-only, secure in production)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := authHeader[len("Bearer "):]
	claims, err := s.authService.ValidateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	user, err := s.userStore.GetUserByID(claims.Sub)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"sub":            user.ID,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
		"roles":          user.Roles,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := s.userStore.CreateUser(req.Username, req.Email, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Authorization endpoint - not fully implemented\n")
}

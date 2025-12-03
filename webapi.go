package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/mail"
	"regexp"
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
	pathAuthorize        = "/oauth/authorize"
	pathRegisterPage     = "/register"

	// Redis Monitor paths
	pathRedisMonitor = "/redis"
	pathRedisInfo    = "/api/redis/info"
	pathRedisKeys    = "/api/redis/keys"
	pathRedisKey     = "/api/redis/key"
	pathRedisPing    = "/api/redis/ping"
	pathRedisStats   = "/api/redis/stats"

	// Game paths
	pathTetris = "/tetris"
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
	s.mux.HandleFunc(pathRegisterPage, s.handleRegisterPage)
	s.mux.HandleFunc(pathAuthorize, s.handleAuthorize)

	// Redis Monitor routes
	s.mux.HandleFunc(pathRedisMonitor, s.handleRedisMonitor)
	s.mux.HandleFunc(pathRedisInfo, s.handleRedisInfo)
	s.mux.HandleFunc(pathRedisKeys, s.handleRedisKeys)
	s.mux.HandleFunc(pathRedisKey, s.handleRedisKeyValue)
	s.mux.HandleFunc(pathRedisPing, s.handleRedisPing)
	s.mux.HandleFunc(pathRedisStats, s.handleRedisStats)

	// Game routes
	s.mux.HandleFunc(pathTetris, s.handleTetris)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "./static/index.html")
}

func (s *Server) handleHello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get(queryParamName)
	if name == "" {
		name = defaultName
	}
	// XSS 방지: HTML 이스케이프 적용
	fmt.Fprintf(w, "Hello, %s!\n", html.EscapeString(name))
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

	// 브루트포스 방어: 로그인 시도 횟수 확인
	blocked, remaining, err := s.loginTracker.IsBlocked(username)
	if err != nil {
		log.Printf("Login tracker error: %v", err)
	}
	if blocked {
		lockoutTime := s.loginTracker.GetLockoutTimeRemaining(username)
		w.Header().Set("Retry-After", fmt.Sprintf("%d", lockoutTime))
		http.Error(w, fmt.Sprintf("Too many failed login attempts. Try again in %d seconds.", lockoutTime), http.StatusTooManyRequests)
		return
	}

	user, err := s.authService.Authenticate(username, password)
	if err != nil {
		// 실패한 로그인 시도 기록
		s.loginTracker.RecordFailedAttempt(username)
		log.Printf("Failed login attempt for user %s (remaining: %d)", username, remaining-1)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// 로그인 성공 시 실패 카운터 초기화
	s.loginTracker.ResetAttempts(username)

	idToken, err := s.authService.GenerateIDToken(user)
	if err != nil {
		log.Printf("Failed to generate ID token: %v", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	accessToken, err := s.authService.GenerateAccessToken(user)
	if err != nil {
		log.Printf("Failed to generate access token: %v", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Create session in Redis
	sessionID, err := s.sessionStore.CreateSession(user.ID, 0)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Set session cookie (HTTP-only, secure in production)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   s.config.TLS.Enabled, // HTTPS일 때만 Secure 설정
		SameSite: http.SameSiteStrictMode,
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

// 입력 검증 함수들
func validateUsername(username string) bool {
	if len(username) < 3 || len(username) > 30 {
		return false
	}
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_]+$`, username)
	return matched
}

func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	// 최소 하나의 숫자와 특수문자 포함
	hasDigit, _ := regexp.MatchString(`[0-9]`, password)
	hasSpecial, _ := regexp.MatchString(`[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;'/~]`, password)
	return hasDigit && hasSpecial
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
		log.Printf("JSON decode error: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 서버 측 입력 검증
	if !validateUsername(req.Username) {
		http.Error(w, "Invalid username: must be 3-30 characters (letters, numbers, underscores)", http.StatusBadRequest)
		return
	}

	if !validateEmail(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	if !validatePassword(req.Password) {
		http.Error(w, "Password must be at least 8 characters with a number and special character", http.StatusBadRequest)
		return
	}

	user, err := s.userStore.CreateUser(req.Username, req.Email, req.Password)
	if err != nil {
		// 민감 정보 노출 방지: 일반적인 에러 메시지 반환
		log.Printf("Registration failed for user %s: %v", req.Username, err)
		http.Error(w, "Registration failed", http.StatusBadRequest)
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

func (s *Server) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/register.html")
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Authorization endpoint - not fully implemented\n")
}

func (s *Server) handleTetris(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/tetris.html")
}

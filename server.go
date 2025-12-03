package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Server struct {
	config       *Config
	mux          *http.ServeMux
	shutdownCh   chan struct{}
	userStore    *UserStore
	authService  *AuthService
	sessionStore *SessionStore
	redisMonitor *RedisMonitor
	rateLimiter  *RateLimiter
	loginTracker *LoginAttemptTracker
}

func NewServer(config *Config) (*Server, error) {
	userStore, err := NewUserStore(config.Security.UserStoreKey, config.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create user store: %w", err)
	}

	authService := NewAuthService(userStore, config.Security.JWTSecret)

	sessionStore, err := NewSessionStore(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create session store: %w", err)
	}

	redisMonitor, err := NewRedisMonitor(config)
	if err != nil {
		log.Printf("Warning: Redis monitor initialization failed: %v", err)
		// Continue without Redis monitor - it's not critical
	}

	// Initialize rate limiter and login tracker using session store's Redis client
	var redisClient = sessionStore.GetClient()
	rateLimiter := NewRateLimiter(redisClient, 100) // 100 requests per minute
	loginTracker := NewLoginAttemptTracker(redisClient, 5, 15*time.Minute) // 5 attempts, 15 min lockout

	s := &Server{
		config:       config,
		mux:          http.NewServeMux(),
		shutdownCh:   make(chan struct{}),
		userStore:    userStore,
		authService:  authService,
		sessionStore: sessionStore,
		redisMonitor: redisMonitor,
		rateLimiter:  rateLimiter,
		loginTracker: loginTracker,
	}
	s.routes()
	return s, nil
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
		log.Printf("Completed in %v", time.Since(start))
	})
}

// securityHeadersMiddleware adds security headers to all responses
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clickjacking 방지
		w.Header().Set("X-Frame-Options", "DENY")

		// MIME 타입 스니핑 방지
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// XSS 보호 (레거시 브라우저용)
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';")

		// Referrer 정책
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// 기능 정책
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// HTTPS 사용 시 HSTS 설정
		if s.config.TLS.Enabled {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// sessionMiddleware validates the session cookie and adds user ID to request context
/* func (s *Server) sessionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Error(w, "Unauthorized: no session", http.StatusUnauthorized)
			return
		}

		userID, err := s.sessionStore.GetSession(cookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized: invalid session", http.StatusUnauthorized)
			return
		}

		// Refresh session on each request
		s.sessionStore.RefreshSession(cookie.Value, 0)

		// Add user ID to request context
		ctx := context.WithValue(r.Context(), "userID", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
} */

func (s *Server) Start() error {
	srv := &http.Server{
		Addr:    s.config.Server.Address,
		Handler: s.securityHeadersMiddleware(s.csrfMiddleware(s.rateLimitMiddleware(s.loggingMiddleware(s.mux)))),
	}

	// Channel to listen for server errors
	serverErrors := make(chan error, 1)

	// Start server
	go func() {
		if s.config.TLS.Enabled {
			log.Printf("Starting secure server (HTTPS) on %s", s.config.Server.Address)
			serverErrors <- srv.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile)
		} else {
			log.Printf("Starting server (HTTP) on %s", s.config.Server.Address)
			serverErrors <- srv.ListenAndServe()
		}
	}()

	// Blocking wait for shutdown signal or server error
	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)
	case <-s.shutdownCh:
		log.Println("Shutdown signal received")

		// Create a context with timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			// Force close if graceful shutdown fails
			srv.Close()
			return fmt.Errorf("could not stop server gracefully: %w", err)
		}
		log.Println("Server stopped gracefully")
		return nil
	}
}

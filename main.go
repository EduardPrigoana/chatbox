package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/microcosm-cc/bluemonday"
	"golang.org/x/time/rate"
)

type Message struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Message   string    `json:"message"`
	Contact   string    `json:"contact"`
	Avatar    string    `json:"avatar"`
	SentAt    time.Time `json:"sent_at"`
}

type RateLimiter struct {
	visitors map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

var (
	db            *sql.DB
	sanitizer     *bluemonday.Policy
	rateLimiter   *RateLimiter
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	urlRegex      = regexp.MustCompile(`^https?://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+$`)
	htmlRegex     = regexp.MustCompile(`<[^>]*>|&lt;|&gt;|&#?\w+;`)
)

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
}

func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = limiter
	}

	return limiter
}

func (rl *RateLimiter) CleanupRoutine() {
	for {
		time.Sleep(5 * time.Minute)
		rl.mu.Lock()
		for ip, limiter := range rl.visitors {
			if limiter.Tokens() == float64(rl.burst) {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func initDB() error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable is required")
	}

	var err error
	db, err = sql.Open("postgres", databaseURL)
	if err != nil {
		return err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db.Ping()
}

func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

func isAllowedOrigin(origin string) bool {
	if origin == "" {
		return false
	}

	origin = strings.TrimPrefix(origin, "https://")
	origin = strings.TrimPrefix(origin, "http://")

	if idx := strings.Index(origin, ":"); idx != -1 {
		origin = origin[:idx]
	}

	return origin == "prigoana.com" || strings.HasSuffix(origin, ".prigoana.com")
}

func containsHTML(s string) bool {
	return htmlRegex.MatchString(s)
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		limiter := rateLimiter.GetLimiter(ip)

		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" && isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func validateMessage(msg *Message) error {
	msg.Name = strings.TrimSpace(msg.Name)
	msg.Message = strings.TrimSpace(msg.Message)
	msg.Contact = strings.TrimSpace(msg.Contact)
	msg.Avatar = strings.TrimSpace(msg.Avatar)

	if containsHTML(msg.Name) {
		return fmt.Errorf("HTML tags are not allowed in name")
	}

	if containsHTML(msg.Message) {
		return fmt.Errorf("HTML tags are not allowed in message")
	}

	msg.Name = sanitizer.Sanitize(msg.Name)
	msg.Message = sanitizer.Sanitize(msg.Message)

	if len(msg.Name) < 2 || len(msg.Name) > 100 {
		return fmt.Errorf("name must be between 2 and 100 characters")
	}

	if len(msg.Message) < 1 || len(msg.Message) > 1000 {
		return fmt.Errorf("message must be between 1 and 1000 characters")
	}

	if msg.Contact != "" {
		if containsHTML(msg.Contact) {
			return fmt.Errorf("HTML tags are not allowed in contact")
		}
		if !emailRegex.MatchString(msg.Contact) && !urlRegex.MatchString(msg.Contact) {
			return fmt.Errorf("invalid email or website format")
		}
		if len(msg.Contact) > 255 {
			return fmt.Errorf("contact must be less than 255 characters")
		}
	}

	if msg.Avatar != "" {
		if !urlRegex.MatchString(msg.Avatar) {
			return fmt.Errorf("invalid avatar URL")
		}
		if len(msg.Avatar) > 500 {
			return fmt.Errorf("avatar URL must be less than 500 characters")
		}
	}

	return nil
}

func handlePostMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := validateMessage(&msg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ip := getClientIP(r)
	userAgent := r.UserAgent()

	query := `INSERT INTO messages (name, message, contact, avatar, ip_address, user_agent)
	          VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, sent_at`

	err := db.QueryRow(query, msg.Name, msg.Message, msg.Contact, msg.Avatar, ip, userAgent).
		Scan(&msg.ID, &msg.SentAt)

	if err != nil {
		log.Printf("Database error: %v", err)
		http.Error(w, "Failed to save message", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

func handleGetMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := `SELECT id, name, message, contact, avatar, sent_at
	          FROM messages
	          ORDER BY sent_at DESC
	          LIMIT 100`

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Database error: %v", err)
		http.Error(w, "Failed to fetch messages", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	messages := []Message{}
	for rows.Next() {
		var msg Message
		err := rows.Scan(&msg.ID, &msg.Name, &msg.Message, &msg.Contact, &msg.Avatar, &msg.SentAt)
		if err != nil {
			log.Printf("Scan error: %v", err)
			continue
		}
		messages = append(messages, msg)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://prigoana.com/", http.StatusMovedPermanently)
}

func main() {
	if err := initDB(); err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	sanitizer = bluemonday.StrictPolicy()
	rateLimiter = NewRateLimiter(rate.Limit(10), 20)
	go rateLimiter.CleanupRoutine()

	port := getEnv("PORT", "8080")

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/messages", corsMiddleware(rateLimitMiddleware(handleGetMessages)))
	http.HandleFunc("/api/messages/post", corsMiddleware(rateLimitMiddleware(handlePostMessage)))

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

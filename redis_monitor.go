package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisMonitor provides monitoring capabilities for Redis
type RedisMonitor struct {
	client *redis.Client
	ctx    context.Context
}

// RedisInfo represents the parsed Redis INFO command output
type RedisInfo struct {
	Server      ServerInfo      `json:"server"`
	Clients     ClientsInfo     `json:"clients"`
	Memory      MemoryInfo      `json:"memory"`
	Stats       StatsInfo       `json:"stats"`
	Replication ReplicationInfo `json:"replication"`
	CPU         CPUInfo         `json:"cpu"`
	Keyspace    []KeyspaceInfo  `json:"keyspace"`
}

type ServerInfo struct {
	RedisVersion    string `json:"redis_version"`
	RedisMode       string `json:"redis_mode"`
	OS              string `json:"os"`
	TCPPort         int    `json:"tcp_port"`
	UptimeInSeconds int64  `json:"uptime_in_seconds"`
	UptimeInDays    int    `json:"uptime_in_days"`
	ProcessID       int    `json:"process_id"`
}

type ClientsInfo struct {
	ConnectedClients         int   `json:"connected_clients"`
	ClientRecentMaxInputBuf  int64 `json:"client_recent_max_input_buffer"`
	ClientRecentMaxOutputBuf int64 `json:"client_recent_max_output_buffer"`
	BlockedClients           int   `json:"blocked_clients"`
}

type MemoryInfo struct {
	UsedMemory            int64   `json:"used_memory"`
	UsedMemoryHuman       string  `json:"used_memory_human"`
	UsedMemoryRSS         int64   `json:"used_memory_rss"`
	UsedMemoryRSSHuman    string  `json:"used_memory_rss_human"`
	UsedMemoryPeak        int64   `json:"used_memory_peak"`
	UsedMemoryPeakHuman   string  `json:"used_memory_peak_human"`
	TotalSystemMemory     int64   `json:"total_system_memory"`
	TotalSystemMemoryHuman string `json:"total_system_memory_human"`
	UsedMemoryPercent     float64 `json:"used_memory_percent"`
	MaxMemory             int64   `json:"maxmemory"`
	MaxMemoryHuman        string  `json:"maxmemory_human"`
	MaxMemoryPolicy       string  `json:"maxmemory_policy"`
}

type StatsInfo struct {
	TotalConnectionsReceived int64   `json:"total_connections_received"`
	TotalCommandsProcessed   int64   `json:"total_commands_processed"`
	InstantaneousOpsPerSec   int64   `json:"instantaneous_ops_per_sec"`
	TotalNetInputBytes       int64   `json:"total_net_input_bytes"`
	TotalNetOutputBytes      int64   `json:"total_net_output_bytes"`
	InstantaneousInputKbps   float64 `json:"instantaneous_input_kbps"`
	InstantaneousOutputKbps  float64 `json:"instantaneous_output_kbps"`
	RejectedConnections      int64   `json:"rejected_connections"`
	ExpiredKeys              int64   `json:"expired_keys"`
	EvictedKeys              int64   `json:"evicted_keys"`
	KeyspaceHits             int64   `json:"keyspace_hits"`
	KeyspaceMisses           int64   `json:"keyspace_misses"`
	HitRate                  float64 `json:"hit_rate"`
}

type ReplicationInfo struct {
	Role             string `json:"role"`
	ConnectedSlaves  int    `json:"connected_slaves"`
	MasterLinkStatus string `json:"master_link_status,omitempty"`
}

type CPUInfo struct {
	UsedCPUSys       float64 `json:"used_cpu_sys"`
	UsedCPUUser      float64 `json:"used_cpu_user"`
	UsedCPUSysChild  float64 `json:"used_cpu_sys_children"`
	UsedCPUUserChild float64 `json:"used_cpu_user_children"`
}

type KeyspaceInfo struct {
	DB      string `json:"db"`
	Keys    int64  `json:"keys"`
	Expires int64  `json:"expires"`
	AvgTTL  int64  `json:"avg_ttl"`
}

type KeyInfo struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	TTL   int64  `json:"ttl"`
	Value string `json:"value,omitempty"`
}

// NewRedisMonitor creates a new Redis monitor
func NewRedisMonitor(config *Config) (*RedisMonitor, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", config.Redis.Host, config.Redis.Port),
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	ctx := context.Background()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisMonitor{
		client: client,
		ctx:    ctx,
	}, nil
}

// GetInfo returns parsed Redis INFO
func (m *RedisMonitor) GetInfo() (*RedisInfo, error) {
	info, err := m.client.Info(m.ctx).Result()
	if err != nil {
		return nil, err
	}

	return m.parseInfo(info)
}

func (m *RedisMonitor) parseInfo(info string) (*RedisInfo, error) {
	result := &RedisInfo{}
	lines := strings.Split(info, "\n")
	section := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			section = strings.TrimPrefix(line, "# ")
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]

		switch section {
		case "Server":
			m.parseServerInfo(result, key, value)
		case "Clients":
			m.parseClientsInfo(result, key, value)
		case "Memory":
			m.parseMemoryInfo(result, key, value)
		case "Stats":
			m.parseStatsInfo(result, key, value)
		case "Replication":
			m.parseReplicationInfo(result, key, value)
		case "CPU":
			m.parseCPUInfo(result, key, value)
		case "Keyspace":
			m.parseKeyspaceInfo(result, key, value)
		}
	}

	// Calculate hit rate
	total := result.Stats.KeyspaceHits + result.Stats.KeyspaceMisses
	if total > 0 {
		result.Stats.HitRate = float64(result.Stats.KeyspaceHits) / float64(total) * 100
	}

	// Calculate memory percent
	if result.Memory.MaxMemory > 0 {
		result.Memory.UsedMemoryPercent = float64(result.Memory.UsedMemory) / float64(result.Memory.MaxMemory) * 100
	} else if result.Memory.TotalSystemMemory > 0 {
		result.Memory.UsedMemoryPercent = float64(result.Memory.UsedMemory) / float64(result.Memory.TotalSystemMemory) * 100
	}

	return result, nil
}

func (m *RedisMonitor) parseServerInfo(info *RedisInfo, key, value string) {
	switch key {
	case "redis_version":
		info.Server.RedisVersion = value
	case "redis_mode":
		info.Server.RedisMode = value
	case "os":
		info.Server.OS = value
	case "tcp_port":
		info.Server.TCPPort, _ = strconv.Atoi(value)
	case "uptime_in_seconds":
		info.Server.UptimeInSeconds, _ = strconv.ParseInt(value, 10, 64)
	case "uptime_in_days":
		info.Server.UptimeInDays, _ = strconv.Atoi(value)
	case "process_id":
		info.Server.ProcessID, _ = strconv.Atoi(value)
	}
}

func (m *RedisMonitor) parseClientsInfo(info *RedisInfo, key, value string) {
	switch key {
	case "connected_clients":
		info.Clients.ConnectedClients, _ = strconv.Atoi(value)
	case "client_recent_max_input_buffer":
		info.Clients.ClientRecentMaxInputBuf, _ = strconv.ParseInt(value, 10, 64)
	case "client_recent_max_output_buffer":
		info.Clients.ClientRecentMaxOutputBuf, _ = strconv.ParseInt(value, 10, 64)
	case "blocked_clients":
		info.Clients.BlockedClients, _ = strconv.Atoi(value)
	}
}

func (m *RedisMonitor) parseMemoryInfo(info *RedisInfo, key, value string) {
	switch key {
	case "used_memory":
		info.Memory.UsedMemory, _ = strconv.ParseInt(value, 10, 64)
	case "used_memory_human":
		info.Memory.UsedMemoryHuman = value
	case "used_memory_rss":
		info.Memory.UsedMemoryRSS, _ = strconv.ParseInt(value, 10, 64)
	case "used_memory_rss_human":
		info.Memory.UsedMemoryRSSHuman = value
	case "used_memory_peak":
		info.Memory.UsedMemoryPeak, _ = strconv.ParseInt(value, 10, 64)
	case "used_memory_peak_human":
		info.Memory.UsedMemoryPeakHuman = value
	case "total_system_memory":
		info.Memory.TotalSystemMemory, _ = strconv.ParseInt(value, 10, 64)
	case "total_system_memory_human":
		info.Memory.TotalSystemMemoryHuman = value
	case "maxmemory":
		info.Memory.MaxMemory, _ = strconv.ParseInt(value, 10, 64)
	case "maxmemory_human":
		info.Memory.MaxMemoryHuman = value
	case "maxmemory_policy":
		info.Memory.MaxMemoryPolicy = value
	}
}

func (m *RedisMonitor) parseStatsInfo(info *RedisInfo, key, value string) {
	switch key {
	case "total_connections_received":
		info.Stats.TotalConnectionsReceived, _ = strconv.ParseInt(value, 10, 64)
	case "total_commands_processed":
		info.Stats.TotalCommandsProcessed, _ = strconv.ParseInt(value, 10, 64)
	case "instantaneous_ops_per_sec":
		info.Stats.InstantaneousOpsPerSec, _ = strconv.ParseInt(value, 10, 64)
	case "total_net_input_bytes":
		info.Stats.TotalNetInputBytes, _ = strconv.ParseInt(value, 10, 64)
	case "total_net_output_bytes":
		info.Stats.TotalNetOutputBytes, _ = strconv.ParseInt(value, 10, 64)
	case "instantaneous_input_kbps":
		info.Stats.InstantaneousInputKbps, _ = strconv.ParseFloat(value, 64)
	case "instantaneous_output_kbps":
		info.Stats.InstantaneousOutputKbps, _ = strconv.ParseFloat(value, 64)
	case "rejected_connections":
		info.Stats.RejectedConnections, _ = strconv.ParseInt(value, 10, 64)
	case "expired_keys":
		info.Stats.ExpiredKeys, _ = strconv.ParseInt(value, 10, 64)
	case "evicted_keys":
		info.Stats.EvictedKeys, _ = strconv.ParseInt(value, 10, 64)
	case "keyspace_hits":
		info.Stats.KeyspaceHits, _ = strconv.ParseInt(value, 10, 64)
	case "keyspace_misses":
		info.Stats.KeyspaceMisses, _ = strconv.ParseInt(value, 10, 64)
	}
}

func (m *RedisMonitor) parseReplicationInfo(info *RedisInfo, key, value string) {
	switch key {
	case "role":
		info.Replication.Role = value
	case "connected_slaves":
		info.Replication.ConnectedSlaves, _ = strconv.Atoi(value)
	case "master_link_status":
		info.Replication.MasterLinkStatus = value
	}
}

func (m *RedisMonitor) parseCPUInfo(info *RedisInfo, key, value string) {
	switch key {
	case "used_cpu_sys":
		info.CPU.UsedCPUSys, _ = strconv.ParseFloat(value, 64)
	case "used_cpu_user":
		info.CPU.UsedCPUUser, _ = strconv.ParseFloat(value, 64)
	case "used_cpu_sys_children":
		info.CPU.UsedCPUSysChild, _ = strconv.ParseFloat(value, 64)
	case "used_cpu_user_children":
		info.CPU.UsedCPUUserChild, _ = strconv.ParseFloat(value, 64)
	}
}

func (m *RedisMonitor) parseKeyspaceInfo(info *RedisInfo, key, value string) {
	// Format: db0:keys=1,expires=0,avg_ttl=0
	if !strings.HasPrefix(key, "db") {
		return
	}

	ks := KeyspaceInfo{DB: key}
	pairs := strings.Split(value, ",")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "keys":
			ks.Keys, _ = strconv.ParseInt(kv[1], 10, 64)
		case "expires":
			ks.Expires, _ = strconv.ParseInt(kv[1], 10, 64)
		case "avg_ttl":
			ks.AvgTTL, _ = strconv.ParseInt(kv[1], 10, 64)
		}
	}
	info.Keyspace = append(info.Keyspace, ks)
}

// GetKeys returns keys matching a pattern with their info
func (m *RedisMonitor) GetKeys(pattern string, count int64) ([]KeyInfo, error) {
	if pattern == "" {
		pattern = "*"
	}
	if count == 0 {
		count = 100
	}

	var cursor uint64
	var keys []string

	for {
		var batch []string
		var err error
		batch, cursor, err = m.client.Scan(m.ctx, cursor, pattern, count).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		if cursor == 0 || int64(len(keys)) >= count {
			break
		}
	}

	if int64(len(keys)) > count {
		keys = keys[:count]
	}

	var result []KeyInfo
	for _, key := range keys {
		keyType, _ := m.client.Type(m.ctx, key).Result()
		ttl, _ := m.client.TTL(m.ctx, key).Result()

		ki := KeyInfo{
			Key:  key,
			Type: keyType,
			TTL:  int64(ttl.Seconds()),
		}

		// Get value preview for string type
		if keyType == "string" {
			val, err := m.client.Get(m.ctx, key).Result()
			if err == nil {
				if len(val) > 100 {
					val = val[:100] + "..."
				}
				ki.Value = val
			}
		}

		result = append(result, ki)
	}

	return result, nil
}

// GetKeyValue returns the value of a specific key
func (m *RedisMonitor) GetKeyValue(key string) (interface{}, string, error) {
	keyType, err := m.client.Type(m.ctx, key).Result()
	if err != nil {
		return nil, "", err
	}

	var value interface{}
	switch keyType {
	case "string":
		value, err = m.client.Get(m.ctx, key).Result()
	case "list":
		value, err = m.client.LRange(m.ctx, key, 0, -1).Result()
	case "set":
		value, err = m.client.SMembers(m.ctx, key).Result()
	case "zset":
		value, err = m.client.ZRangeWithScores(m.ctx, key, 0, -1).Result()
	case "hash":
		value, err = m.client.HGetAll(m.ctx, key).Result()
	default:
		return nil, keyType, fmt.Errorf("unsupported type: %s", keyType)
	}

	return value, keyType, err
}

// GetDBSize returns the number of keys in the current database
func (m *RedisMonitor) GetDBSize() (int64, error) {
	return m.client.DBSize(m.ctx).Result()
}

// Ping checks Redis connectivity
func (m *RedisMonitor) Ping() (time.Duration, error) {
	start := time.Now()
	_, err := m.client.Ping(m.ctx).Result()
	return time.Since(start), err
}

// FlushDB flushes the current database (use with caution!)
func (m *RedisMonitor) FlushDB() error {
	return m.client.FlushDB(m.ctx).Err()
}

// DeleteKey deletes a specific key
func (m *RedisMonitor) DeleteKey(key string) error {
	return m.client.Del(m.ctx, key).Err()
}

// Close closes the Redis connection
func (m *RedisMonitor) Close() error {
	return m.client.Close()
}

// HTTP Handlers for Redis Monitor

func (s *Server) handleRedisMonitor(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/redis-monitor.html")
}

func (s *Server) handleRedisInfo(w http.ResponseWriter, r *http.Request) {
	if s.redisMonitor == nil {
		http.Error(w, "Redis monitor not initialized", http.StatusServiceUnavailable)
		return
	}

	info, err := s.redisMonitor.GetInfo()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get Redis info: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (s *Server) handleRedisKeys(w http.ResponseWriter, r *http.Request) {
	if s.redisMonitor == nil {
		http.Error(w, "Redis monitor not initialized", http.StatusServiceUnavailable)
		return
	}

	pattern := r.URL.Query().Get("pattern")
	countStr := r.URL.Query().Get("count")
	count := int64(100)
	if countStr != "" {
		if c, err := strconv.ParseInt(countStr, 10, 64); err == nil {
			count = c
		}
	}

	keys, err := s.redisMonitor.GetKeys(pattern, count)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get keys: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func (s *Server) handleRedisKeyValue(w http.ResponseWriter, r *http.Request) {
	if s.redisMonitor == nil {
		http.Error(w, "Redis monitor not initialized", http.StatusServiceUnavailable)
		return
	}

	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "Key parameter required", http.StatusBadRequest)
		return
	}

	// Handle DELETE request
	if r.Method == http.MethodDelete {
		err := s.redisMonitor.DeleteKey(key)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to delete key: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": fmt.Sprintf("Key '%s' deleted successfully", key),
		})
		return
	}

	// Handle GET request
	value, keyType, err := s.redisMonitor.GetKeyValue(key)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get key value: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"key":   key,
		"type":  keyType,
		"value": value,
	}

	ttl, _ := s.redisMonitor.client.TTL(s.redisMonitor.ctx, key).Result()
	response["ttl"] = int64(ttl.Seconds())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleRedisPing(w http.ResponseWriter, r *http.Request) {
	if s.redisMonitor == nil {
		http.Error(w, "Redis monitor not initialized", http.StatusServiceUnavailable)
		return
	}

	latency, err := s.redisMonitor.Ping()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"latency_ms": float64(latency.Microseconds()) / 1000.0,
	})
}

func (s *Server) handleRedisStats(w http.ResponseWriter, r *http.Request) {
	if s.redisMonitor == nil {
		http.Error(w, "Redis monitor not initialized", http.StatusServiceUnavailable)
		return
	}

	dbSize, _ := s.redisMonitor.GetDBSize()
	latency, pingErr := s.redisMonitor.Ping()
	info, _ := s.redisMonitor.GetInfo()

	response := map[string]interface{}{
		"db_size":    dbSize,
		"latency_ms": float64(latency.Microseconds()) / 1000.0,
		"connected":  pingErr == nil,
	}

	if info != nil {
		response["ops_per_sec"] = info.Stats.InstantaneousOpsPerSec
		response["connected_clients"] = info.Clients.ConnectedClients
		response["used_memory_human"] = info.Memory.UsedMemoryHuman
		response["hit_rate"] = info.Stats.HitRate
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

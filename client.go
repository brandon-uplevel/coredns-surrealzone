package surrealzone

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("surrealzone")

// Record represents a DNS record from SurrealDB.
type Record struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority"`
	Weight   *int   `json:"weight"`
	Port     *int   `json:"port"`
}

// Zone represents a DNS zone from SurrealDB.
type Zone struct {
	Name       string `json:"name"`
	Serial     int    `json:"serial"`
	Refresh    int    `json:"refresh"`
	Retry      int    `json:"retry"`
	Expire     int    `json:"expire"`
	MinimumTTL int    `json:"minimum_ttl"`
}

// Client handles HTTP communication with SurrealDB.
type Client struct {
	config   *Config
	http     *http.Client
	token    string
	tokenMu  sync.RWMutex
	tokenExp time.Time
}

// NewClient creates a new SurrealDB client.
func NewClient(config *Config) *Client {
	return &Client{
		config: config,
		http: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

// Connect signs in and acquires a JWT token.
func (c *Client) Connect() error {
	return c.signin()
}

// Lookup queries SurrealDB for DNS records matching name and type.
func (c *Client) Lookup(name, qtype string) ([]Record, error) {
	var query string
	if qtype != "ANY" {
		query = fmt.Sprintf("SELECT name, type, content, ttl, priority, weight, port FROM record WHERE name = '%s' AND disabled = false AND type = '%s';",
			escapeSurql(name), escapeSurql(qtype))
	} else {
		query = fmt.Sprintf("SELECT name, type, content, ttl, priority, weight, port FROM record WHERE name = '%s' AND disabled = false;",
			escapeSurql(name))
	}

	results, err := c.query(query)
	if err != nil {
		return nil, err
	}

	return parseRecords(results)
}

// escapeSurql escapes single quotes for SurrealQL string literals.
func escapeSurql(s string) string {
	return strings.ReplaceAll(s, "'", "\\'")
}

// ZoneExists checks if a zone exists in SurrealDB.
func (c *Client) ZoneExists(zoneName string) (bool, error) {
	results, err := c.query(
		fmt.Sprintf("SELECT count() FROM zone WHERE name = '%s' AND active = true GROUP ALL;", escapeSurql(zoneName)),
	)
	if err != nil {
		return false, err
	}

	// Parse count result
	var counts []struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(results, &counts); err != nil {
		return false, err
	}
	return len(counts) > 0 && counts[0].Count > 0, nil
}

// GetSOA builds an SOA record for a zone from SurrealDB.
func (c *Client) GetSOA(zoneName string) (dns.RR, error) {
	results, err := c.query(
		fmt.Sprintf("SELECT name, serial, refresh, retry, expire, minimum_ttl FROM zone WHERE name = '%s' AND active = true LIMIT 1;", escapeSurql(zoneName)),
	)
	if err != nil {
		return nil, err
	}

	var zones []Zone
	if err := json.Unmarshal(results, &zones); err != nil {
		return nil, err
	}
	if len(zones) == 0 {
		return nil, fmt.Errorf("zone %s not found", zoneName)
	}

	z := zones[0]

	// Get the first NS record for the MNAME field
	nsRecords, err := c.Lookup(zoneName, "NS")
	mname := "ns1.hellojade.ai."
	if err == nil && len(nsRecords) > 0 {
		mname = nsRecords[0].Content
	}

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zoneName,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    uint32(z.MinimumTTL),
		},
		Ns:      mname,
		Mbox:    dns.Fqdn("hostmaster." + zoneName),
		Serial:  uint32(z.Serial),
		Refresh: uint32(z.Refresh),
		Retry:   uint32(z.Retry),
		Expire:  uint32(z.Expire),
		Minttl:  uint32(z.MinimumTTL),
	}

	return soa, nil
}

// GetZones returns all active zone names from SurrealDB.
func (c *Client) GetZones() ([]string, error) {
	results, err := c.query("SELECT name FROM zone WHERE active = true;")
	if err != nil {
		return nil, err
	}

	var zones []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(results, &zones); err != nil {
		return nil, err
	}

	names := make([]string, len(zones))
	for i, z := range zones {
		names[i] = z.Name
	}
	return names, nil
}

// signin authenticates with SurrealDB.
func (c *Client) signin() error {
	body, _ := json.Marshal(map[string]string{
		"ns":   c.config.Namespace,
		"db":   c.config.Database,
		"user": c.config.Username,
		"pass": c.config.Password,
	})

	req, err := http.NewRequest("POST", c.config.URL+"/signin", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create signin request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("signin request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("signin returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parse signin response: %w", err)
	}

	c.tokenMu.Lock()
	c.token = result.Token
	c.tokenExp = time.Now().Add(50 * time.Minute)
	c.tokenMu.Unlock()

	log.Info("SurrealDB signin successful")
	return nil
}

// getToken returns a valid token, refreshing if needed.
func (c *Client) getToken() string {
	c.tokenMu.RLock()
	token := c.token
	exp := c.tokenExp
	c.tokenMu.RUnlock()

	if time.Now().After(exp) {
		if err := c.signin(); err != nil {
			log.Errorf("Token refresh failed: %v", err)
			return token
		}
		c.tokenMu.RLock()
		token = c.token
		c.tokenMu.RUnlock()
	}

	return token
}

// surrealResponse is the SurrealDB HTTP API response format.
type surrealResponse struct {
	Result json.RawMessage `json:"result"`
	Status string          `json:"status"`
	Time   string          `json:"time"`
}

// query executes a raw SurrealQL query and returns the result array.
func (c *Client) query(surql string) (json.RawMessage, error) {
	token := c.getToken()

	req, err := http.NewRequest("POST", c.config.URL+"/sql", bytes.NewReader([]byte(surql)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/surql")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("surreal-ns", c.config.Namespace)
	req.Header.Set("surreal-db", c.config.Database)

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Re-signin and retry once
		if err := c.signin(); err != nil {
			return nil, fmt.Errorf("re-signin failed: %w", err)
		}
		return c.query(surql) // recursive retry (once, since token is now fresh)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SurrealDB returned %d: %s", resp.StatusCode, string(body))
	}

	body, _ := io.ReadAll(resp.Body)

	var responses []surrealResponse
	if err := json.Unmarshal(body, &responses); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(responses) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	last := responses[len(responses)-1]
	if last.Status != "OK" {
		return nil, fmt.Errorf("query error: %s", string(last.Result))
	}

	return last.Result, nil
}

// parseRecords converts SurrealDB JSON results into Record structs.
func parseRecords(raw json.RawMessage) ([]Record, error) {
	var records []Record
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, err
	}
	return records, nil
}

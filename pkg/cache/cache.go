package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

// SavedLead represents an enriched and verified lead saved to local storage
type SavedLead struct {
	ID          string    `json:"id"`
	FullName    string    `json:"full_name"`
	FirstName   string    `json:"first_name"`
	LastName    string    `json:"last_name"`
	Domain      string    `json:"domain"`
	Email       string    `json:"email"`
	PatternName string    `json:"pattern_name"`
	Confidence  int       `json:"confidence"`
	Status      string    `json:"status"`
	Provider    string    `json:"provider"`
	VerifiedAt  time.Time `json:"verified_at"`
}

// DomainInfo stores learned patterns and provider fingerprints
type DomainInfo struct {
	Domain     string    `json:"domain"`
	Pattern    string    `json:"pattern"`
	Provider   string    `json:"provider"`
	IsCatchAll bool      `json:"is_catch_all"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// StoreData is the serialized schema saved to disk
type StoreData struct {
	Domains map[string]DomainInfo `json:"domains"`
	Leads   []SavedLead           `json:"leads"`
}

// Cache manages thread-safe read/write operations to persistent disk cache
type Cache struct {
	mu       sync.RWMutex
	filePath string
	data     StoreData
}

var (
	defaultCache *Cache
	once         sync.Once
)

// GetDefaultCache returns a singleton cache instance rooted in the user's home directory
func GetDefaultCache() *Cache {
	once.Do(func() {
		home, err := os.UserHomeDir()
		var p string
		if err != nil {
			p = ".poc-recon-cache.json"
		} else {
			dir := filepath.Join(home, ".poc-recon")
			_ = os.MkdirAll(dir, 0755)
			p = filepath.Join(dir, "cache.json")
		}
		defaultCache = NewCache(p)
	})
	return defaultCache
}

// NewCache initializes a cache backed by the specified file path
func NewCache(filePath string) *Cache {
	c := &Cache{
		filePath: filePath,
		data: StoreData{
			Domains: make(map[string]DomainInfo),
			Leads:   make([]SavedLead, 0),
		},
	}
	c.load()
	return c
}

func (c *Cache) load() {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return
	}

	var stored StoreData
	if err := json.Unmarshal(data, &stored); err == nil {
		if stored.Domains == nil {
			stored.Domains = make(map[string]DomainInfo)
		}
		if stored.Leads == nil {
			stored.Leads = make([]SavedLead, 0)
		}
		c.data = stored
	}
}

func (c *Cache) save() error {
	dir := filepath.Dir(c.filePath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	bytes, err := json.MarshalIndent(c.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.filePath, bytes, 0644)
}

// GetDomainPattern retrieves cached pattern and provider info for a given domain
func (c *Cache) GetDomainPattern(domain string) (DomainInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	d := strings.ToLower(strings.TrimSpace(domain))
	info, ok := c.data.Domains[d]
	return info, ok
}

// SetDomainPattern updates or sets the pattern for a given domain
func (c *Cache) SetDomainPattern(domain, pattern, provider string, isCatchAll bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	d := strings.ToLower(strings.TrimSpace(domain))
	c.data.Domains[d] = DomainInfo{
		Domain:     d,
		Pattern:    pattern,
		Provider:   provider,
		IsCatchAll: isCatchAll,
		UpdatedAt:  time.Now(),
	}
	_ = c.save()
}

// SaveLead saves or updates a verified lead in the cache
func (c *Cache) SaveLead(lead SavedLead) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if lead.ID == "" {
		lead.ID = strings.ToLower(lead.Email)
	}
	if lead.VerifiedAt.IsZero() {
		lead.VerifiedAt = time.Now()
	}

	found := false
	for i := range c.data.Leads {
		if strings.EqualFold(c.data.Leads[i].Email, lead.Email) {
			c.data.Leads[i] = lead
			found = true
			break
		}
	}
	if !found {
		c.data.Leads = append([]SavedLead{lead}, c.data.Leads...)
	}

	_ = c.save()
}

// GetLeads returns a slice copy of all saved leads
func (c *Cache) GetLeads() []SavedLead {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]SavedLead, len(c.data.Leads))
	copy(result, c.data.Leads)
	return result
}

// ClearLeads removes all leads from local cache
func (c *Cache) ClearLeads() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data.Leads = make([]SavedLead, 0)
	_ = c.save()
}

// ConvertReconResultToSavedLead converts a models.ReconResult to SavedLead format
func ConvertReconResultToSavedLead(res *models.ReconResult) *SavedLead {
	if res == nil || res.BestCandidate == nil {
		return nil
	}

	cand := res.BestCandidate
	provName := "Unknown"
	if res.Provider != nil && res.Provider.Name != "" {
		provName = res.Provider.Name
	}

	first := res.Person.FirstName
	last := res.Person.LastName
	fullName := res.Person.FullName
	if fullName == "" && first != "" {
		fullName = strings.TrimSpace(first + " " + last)
	}

	return &SavedLead{
		ID:          strings.ToLower(cand.Email),
		FullName:    fullName,
		FirstName:   first,
		LastName:    last,
		Domain:      res.TargetDomain,
		Email:       cand.Email,
		PatternName: cand.PatternName,
		Confidence:  cand.Confidence,
		Status:      string(cand.Status),
		Provider:    provName,
		VerifiedAt:  time.Now(),
	}
}

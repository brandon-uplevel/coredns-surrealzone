package surrealzone

import (
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("surrealzone", setup) }

// Config holds the parsed Corefile configuration.
type Config struct {
	URL       string
	Namespace string
	Database  string
	Username  string
	Password  string
}

func defaultConfig() *Config {
	return &Config{
		URL:       "https://db.hellojade.app",
		Namespace: "hellojade",
		Database:  "dns",
		Username:  "",
		Password:  "",
	}
}

func setup(c *caddy.Controller) error {
	config, err := parseConfig(c)
	if err != nil {
		return plugin.Error("surrealzone", err)
	}

	client := NewClient(config)

	// Create the handler — zones will be populated on startup
	sz := &SurrealZone{
		client: client,
		config: config,
		zones:  []string{},
	}

	// Connect and discover zones at startup
	c.OnStartup(func() error {
		if err := client.Connect(); err != nil {
			return plugin.Error("surrealzone", err)
		}

		z, err := client.GetZones()
		if err != nil {
			return plugin.Error("surrealzone", err)
		}
		sz.zones = z
		log.Infof("Serving %d zones from SurrealDB: %v", len(sz.zones), sz.zones)
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		sz.Next = next
		return sz
	})

	// Refresh zone list periodically
	c.OnStartup(func() error {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				z, err := client.GetZones()
				if err != nil {
					log.Errorf("Failed to refresh zones: %v", err)
					continue
				}
				sz.zones = z
			}
		}()
		return nil
	})

	return nil
}

func parseConfig(c *caddy.Controller) (*Config, error) {
	config := defaultConfig()

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "url":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				config.URL = c.Val()
			case "namespace":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				config.Namespace = c.Val()
			case "database":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				config.Database = c.Val()
			case "username":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				config.Username = c.Val()
			case "password":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				config.Password = c.Val()
			default:
				return nil, c.Errf("unknown surrealzone option: %s", c.Val())
			}
		}
	}

	return config, nil
}

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

// Corefile syntax:
//
//	surrealzone {
//	    url https://db.hellojade.app
//	    namespace hellojade
//	    database dns
//	    username dns_zones
//	    password secret
//	}
func setup(c *caddy.Controller) error {
	config, err := parseConfig(c)
	if err != nil {
		return plugin.Error("surrealzone", err)
	}

	client := NewClient(config)

	// Connect and discover zones at startup
	var zones []string

	c.OnStartup(func() error {
		if err := client.Connect(); err != nil {
			return plugin.Error("surrealzone", err)
		}

		z, err := client.GetZones()
		if err != nil {
			return plugin.Error("surrealzone", err)
		}
		zones = z
		log.Infof("Serving %d zones from SurrealDB: %v", len(zones), zones)
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &SurrealZone{
			Next:   next,
			client: client,
			config: config,
			zones:  zones,
		}
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
				zones = z
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

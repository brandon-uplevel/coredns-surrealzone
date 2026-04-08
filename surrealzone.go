// Package surrealzone implements a CoreDNS plugin that serves DNS zones from SurrealDB.
// It replaces static zone files — records are queried live from the database.
// Place the CoreDNS `cache` plugin before this one to avoid per-query DB hits.
package surrealzone

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// SurrealZone is the plugin handler.
type SurrealZone struct {
	Next   plugin.Handler
	client *Client
	config *Config
	zones  []string // zones we're authoritative for (e.g., ["hellojade.ai."])
}

// ServeDNS implements the plugin.Handler interface.
func (s *SurrealZone) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.QName()
	qtype := state.QType()

	// Check if this query is for one of our zones
	zone := plugin.Zones(s.zones).Matches(qname)
	if zone == "" {
		return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Query SurrealDB for matching records
	records, err := s.client.Lookup(qname, dns.TypeToString[qtype])
	if err != nil {
		log.Errorf("SurrealDB lookup failed for %s %s: %v", qname, dns.TypeToString[qtype], err)
		errorsTotal.Inc()
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return dns.RcodeServerFailure, nil
	}

	queriesTotal.Inc()

	if len(records) > 0 {
		// Build answer records
		for _, rec := range records {
			rr := buildRR(rec)
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// No exact match — try wildcard
	wildcardName := buildWildcard(qname, zone)
	if wildcardName != "" {
		records, err = s.client.Lookup(wildcardName, dns.TypeToString[qtype])
		if err == nil && len(records) > 0 {
			for _, rec := range records {
				rr := buildRR(rec)
				if rr != nil {
					// Rewrite the wildcard name to the actual query name
					rr.Header().Name = qname
					m.Answer = append(m.Answer, rr)
				}
			}
			w.WriteMsg(m)
			return dns.RcodeSuccess, nil
		}
	}

	// No records found — check if the zone exists (for proper NXDOMAIN vs REFUSED)
	zoneExists, _ := s.client.ZoneExists(zone)
	if !zoneExists {
		return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
	}

	// Zone exists but no records — NXDOMAIN with SOA
	m.Rcode = dns.RcodeNameError
	soa, err := s.client.GetSOA(zone)
	if err == nil && soa != nil {
		m.Ns = append(m.Ns, soa)
	}
	w.WriteMsg(m)
	return dns.RcodeNameError, nil
}

// Name implements the plugin.Handler interface.
func (s *SurrealZone) Name() string { return "surrealzone" }

// buildWildcard constructs the wildcard name for a query.
// e.g., "random.hellojade.ai." in zone "hellojade.ai." → "*.hellojade.ai."
func buildWildcard(qname, zone string) string {
	if qname == zone {
		return ""
	}
	// Strip the first label and prepend *
	idx := strings.Index(qname, ".")
	if idx == -1 {
		return ""
	}
	return "*." + qname[idx+1:]
}

// buildRR converts a SurrealDB record into a dns.RR.
func buildRR(rec Record) dns.RR {
	hdr := dns.RR_Header{
		Name:   rec.Name,
		Rrtype: dns.StringToType[rec.Type],
		Class:  dns.ClassINET,
		Ttl:    uint32(rec.TTL),
	}

	switch rec.Type {
	case "A":
		ip := net.ParseIP(rec.Content)
		if ip == nil {
			return nil
		}
		return &dns.A{Hdr: hdr, A: ip.To4()}

	case "AAAA":
		ip := net.ParseIP(rec.Content)
		if ip == nil {
			return nil
		}
		return &dns.AAAA{Hdr: hdr, AAAA: ip}

	case "CNAME":
		return &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(rec.Content)}

	case "MX":
		prio := uint16(10)
		if rec.Priority != nil {
			prio = uint16(*rec.Priority)
		}
		return &dns.MX{Hdr: hdr, Preference: prio, Mx: dns.Fqdn(rec.Content)}

	case "TXT":
		return &dns.TXT{Hdr: hdr, Txt: []string{rec.Content}}

	case "NS":
		return &dns.NS{Hdr: hdr, Ns: dns.Fqdn(rec.Content)}

	case "SRV":
		prio := uint16(0)
		weight := uint16(0)
		port := uint16(0)
		if rec.Priority != nil {
			prio = uint16(*rec.Priority)
		}
		if rec.Weight != nil {
			weight = uint16(*rec.Weight)
		}
		if rec.Port != nil {
			port = uint16(*rec.Port)
		}
		return &dns.SRV{Hdr: hdr, Priority: prio, Weight: weight, Port: port, Target: dns.Fqdn(rec.Content)}

	case "CAA":
		// Content format: "0 issue letsencrypt.org"
		parts := strings.SplitN(rec.Content, " ", 3)
		if len(parts) != 3 {
			return nil
		}
		flag, _ := strconv.ParseUint(parts[0], 10, 8)
		return &dns.CAA{Hdr: hdr, Flag: uint8(flag), Tag: parts[1], Value: parts[2]}

	case "PTR":
		return &dns.PTR{Hdr: hdr, Ptr: dns.Fqdn(rec.Content)}

	default:
		// Unsupported type — try generic RR from string
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", rec.Name, rec.TTL, rec.Type, rec.Content))
		if err != nil {
			return nil
		}
		return rr
	}
}

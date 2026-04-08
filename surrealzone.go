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
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/transfer"
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

	queriesTotal.Inc()

	// Handle SOA queries directly — SOA is constructed from the zone table, not the record table
	if qtype == dns.TypeSOA {
		soa, err := s.client.GetSOA(zone)
		if err != nil {
			log.Errorf("SurrealDB SOA lookup failed for %s: %v", zone, err)
			errorsTotal.Inc()
			m.Rcode = dns.RcodeServerFailure
			w.WriteMsg(m)
			return dns.RcodeServerFailure, nil
		}
		m.Answer = append(m.Answer, soa)
		s.addNSAuthority(m, zone)
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// Handle NS queries for the zone apex
	if qtype == dns.TypeNS && qname == zone {
		nsRecords, err := s.client.Lookup(zone, "NS")
		if err != nil {
			log.Errorf("SurrealDB NS lookup failed for %s: %v", zone, err)
			errorsTotal.Inc()
			m.Rcode = dns.RcodeServerFailure
			w.WriteMsg(m)
			return dns.RcodeServerFailure, nil
		}
		for _, rec := range nsRecords {
			rr := buildRR(rec)
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// Query SurrealDB for matching records
	records, err := s.client.Lookup(qname, dns.TypeToString[qtype])
	if err != nil {
		log.Errorf("SurrealDB lookup failed for %s %s: %v", qname, dns.TypeToString[qtype], err)
		errorsTotal.Inc()
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return dns.RcodeServerFailure, nil
	}

	if len(records) > 0 {
		// Build answer records
		for _, rec := range records {
			rr := buildRR(rec)
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		// Add NS authority section for positive responses
		s.addNSAuthority(m, zone)
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// ALIAS/ANAME flattening — synthesize A/AAAA at zone apex from an ALIAS target
	if (qtype == dns.TypeA || qtype == dns.TypeAAAA) && qname == zone {
		aliasRecords, aliasErr := s.client.Lookup(qname, "ALIAS")
		if aliasErr == nil && len(aliasRecords) > 0 {
			target := aliasRecords[0].Content
			resolved := s.resolveExternal(target, qtype)
			for _, rr := range resolved {
				rr.Header().Name = qname
				rr.Header().Ttl = uint32(aliasRecords[0].TTL)
				m.Answer = append(m.Answer, rr)
			}
			if len(m.Answer) > 0 {
				s.addNSAuthority(m, zone)
				w.WriteMsg(m)
				return dns.RcodeSuccess, nil
			}
		}
	}

	// Check if the record is a CNAME (regardless of qtype) — CNAME chasing
	if qtype != dns.TypeCNAME {
		cnameRecords, cnameErr := s.client.Lookup(qname, "CNAME")
		if cnameErr == nil && len(cnameRecords) > 0 {
			cname := cnameRecords[0]
			cnameRR := buildRR(cname)
			if cnameRR != nil {
				m.Answer = append(m.Answer, cnameRR)
				// Chase the CNAME if target is in-zone
				target := dns.Fqdn(cname.Content)
				if dns.IsSubDomain(zone, target) {
					targetRecords, targetErr := s.client.Lookup(target, dns.TypeToString[qtype])
					if targetErr == nil {
						for _, rec := range targetRecords {
							rr := buildRR(rec)
							if rr != nil {
								m.Answer = append(m.Answer, rr)
							}
						}
					}
				}
			}
			s.addNSAuthority(m, zone)
			w.WriteMsg(m)
			return dns.RcodeSuccess, nil
		}
	}

	// No exact match — try wildcard (walk up labels)
	for _, wildcardName := range buildWildcards(qname, zone) {
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
			s.addNSAuthority(m, zone)
			w.WriteMsg(m)
			return dns.RcodeSuccess, nil
		}
	}

	// No records found — check if the zone exists (for proper NXDOMAIN vs REFUSED)
	zoneExists, _ := s.client.ZoneExists(zone)
	if !zoneExists {
		return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
	}

	// Distinguish NODATA (name exists, type doesn't) from NXDOMAIN (name doesn't exist)
	// Check if ANY records exist for this name
	anyRecords, _ := s.client.Lookup(qname, "ANY")
	if len(anyRecords) > 0 {
		// NODATA — name exists but not this type. Return NOERROR with SOA in authority (RFC 2308)
		m.Rcode = dns.RcodeSuccess
		soa, err := s.client.GetSOA(zone)
		if err == nil && soa != nil {
			m.Ns = append(m.Ns, soa)
		}
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// NXDOMAIN — name doesn't exist at all
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

// Transfer implements transfer.Transferer for AXFR/IXFR zone transfers.
func (s *SurrealZone) Transfer(zone string, serial uint32) (<-chan []dns.RR, error) {
	// Check if we're authoritative for this zone
	if plugin.Zones(s.zones).Matches(zone) == "" {
		return nil, transfer.ErrNotAuthoritative
	}

	// Get current serial
	currentSerial, err := s.client.GetZoneSerial(zone)
	if err != nil {
		return nil, err
	}

	ch := make(chan []dns.RR)

	go func() {
		defer close(ch)

		soa, err := s.client.GetSOA(zone)
		if err != nil {
			return
		}

		// IXFR: if requested serial >= current, send SOA only (already up to date)
		if serial != 0 && serial >= currentSerial {
			ch <- []dns.RR{soa}
			return
		}

		// AXFR: send all records bookended by SOA
		// First SOA
		ch <- []dns.RR{soa}

		// All records
		records, err := s.client.GetAllRecords(zone)
		if err != nil {
			log.Errorf("AXFR GetAllRecords failed for %s: %v", zone, err)
			return
		}
		log.Infof("AXFR: transferring %d records for zone %s", len(records), zone)

		batch := make([]dns.RR, 0, 50)
		for _, rec := range records {
			rr := buildRR(rec)
			if rr == nil {
				continue
			}
			batch = append(batch, rr)
			if len(batch) >= 50 {
				ch <- batch
				batch = make([]dns.RR, 0, 50)
			}
		}
		if len(batch) > 0 {
			ch <- batch
		}

		// Closing SOA
		ch <- []dns.RR{soa}
	}()

	return ch, nil
}

// addNSAuthority adds NS records to the authority section of a response.
func (s *SurrealZone) addNSAuthority(m *dns.Msg, zone string) {
	nsRecords, err := s.client.Lookup(zone, "NS")
	if err != nil {
		return
	}
	for _, rec := range nsRecords {
		rr := buildRR(rec)
		if rr != nil {
			m.Ns = append(m.Ns, rr)
		}
	}
}

// resolveExternal resolves a hostname using the system resolver.
// Used for ALIAS/ANAME flattening where the target is outside our zones.
func (s *SurrealZone) resolveExternal(target string, qtype uint16) []dns.RR {
	c := new(dns.Client)
	c.Timeout = 2 * time.Second
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(target), qtype)
	m.RecursionDesired = true

	// Try system resolvers from /etc/resolv.conf
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		log.Warningf("ALIAS resolution failed for %s: %v", target, err)
		return nil
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil
	}
	// Filter to only A/AAAA answers
	var results []dns.RR
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == qtype {
			results = append(results, rr)
		}
	}
	return results
}

// buildWildcards returns all possible wildcard names for a query, walking up from
// the most specific to least specific.
// e.g., "a.b.c.hellojade.ai." in zone "hellojade.ai." → ["*.b.c.hellojade.ai.", "*.c.hellojade.ai.", "*.hellojade.ai."]
func buildWildcards(qname, zone string) []string {
	if qname == zone {
		return nil
	}
	var wildcards []string
	name := qname
	for {
		idx := strings.Index(name, ".")
		if idx == -1 {
			break
		}
		rest := name[idx+1:]
		if rest == "" {
			break
		}
		wc := "*." + rest
		wildcards = append(wildcards, wc)
		if rest == zone {
			break
		}
		name = rest
	}
	return wildcards
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
		return &dns.TXT{Hdr: hdr, Txt: splitTXT(rec.Content)}

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

	case "HTTPS":
		// Content format: "1 . alpn=h2,h3" or "1 target.example.com. alpn=h2"
		svcb, err := dns.NewRR(fmt.Sprintf("%s %d IN HTTPS %s", rec.Name, rec.TTL, rec.Content))
		if err != nil {
			return nil
		}
		return svcb

	case "SVCB":
		svcb, err := dns.NewRR(fmt.Sprintf("%s %d IN SVCB %s", rec.Name, rec.TTL, rec.Content))
		if err != nil {
			return nil
		}
		return svcb

	default:
		// Unsupported type — try generic RR from string
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", rec.Name, rec.TTL, rec.Type, rec.Content))
		if err != nil {
			return nil
		}
		return rr
	}
}

// splitTXT splits a TXT string into 255-byte chunks per RFC 4408.
// DNS TXT RDATA is a sequence of <length><string> pairs where each string is max 255 bytes.
func splitTXT(s string) []string {
	if len(s) <= 255 {
		return []string{s}
	}
	var chunks []string
	for len(s) > 0 {
		l := len(s)
		if l > 255 {
			l = 255
		}
		chunks = append(chunks, s[:l])
		s = s[l:]
	}
	return chunks
}

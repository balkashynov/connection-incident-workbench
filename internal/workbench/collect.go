package workbench

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
)

type CollectOptions struct {
	Role, IncidentID, Host, Address, Router, Socket string
	Port                                            uint16
	Timeout                                         time.Duration
}

func classify(err error) (State, string) {
	if err == nil {
		return Observed, ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return TimedOut, "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return TimedOut, "timeout"
	}
	if errors.Is(err, os.ErrPermission) || local.IsAccessDeniedError(err) {
		return Denied, "permission_denied"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return Failed, "refused"
	}
	return Failed, "unavailable"
}

func Collect(ctx context.Context, opt CollectOptions) (Bundle, error) {
	token := make([]byte, 8)
	if _, err := rand.Read(token); err != nil {
		return Bundle{}, err
	}
	b := Bundle{SchemaVersion: 1, ToolVersion: Version, ClientVersion: "1.104.1", ID: opt.Role + "-" + hex.EncodeToString(token), IncidentID: opt.IncidentID, Role: opt.Role, Platform: runtime.GOOS, Machine: "local-" + opt.Role, Router: opt.Router, Target: Target{opt.Host, opt.Address, opt.Port}, Start: time.Now().UTC(), Redaction: "local"}
	b.End = b.Start
	if err := b.Validate(); err != nil {
		return b, err
	}
	if opt.Timeout <= 0 || opt.Timeout > 30*time.Second {
		return b, errors.New("probe timeout must be between 0 and 30 seconds")
	}
	lc := &local.Client{Socket: opt.Socket, UseSocketOnly: opt.Socket != ""}
	probe := func(kind string, run func(context.Context) (Facts, State, string)) {
		start := time.Now()
		c, cancel := context.WithTimeout(ctx, opt.Timeout)
		f, state, code := run(c)
		cancel()
		b.Observations = append(b.Observations, Observation{ID: kind, Kind: kind, Method: methods[kind], State: state, Start: start.UTC(), End: time.Now().UTC(), DurationMS: time.Since(start).Milliseconds(), ErrorCode: code, Facts: f})
	}
	probe("daemon", func(c context.Context) (Facts, State, string) {
		s, err := lc.StatusWithoutPeers(c)
		if err != nil {
			state, code := classify(err)
			return Facts{}, state, code
		}
		if s == nil {
			return Facts{}, Failed, "unavailable"
		}
		node := ""
		if len(s.TailscaleIPs) > 0 {
			node = s.TailscaleIPs[0].String()
			b.Machine = node
		}
		backend := s.BackendState
		if !oneOf(backend, "NoState", "NeedsLogin", "NeedsMachineAuth", "Stopped", "Starting", "Running", "InUseOtherUser") {
			backend = "unknown"
		}
		version := s.Version
		if !versionPattern.MatchString(version) {
			version = "unknown"
		}
		return Facts{Backend: backend, DaemonVersion: version, Node: node}, Observed, ""
	})
	probe("dns_os", func(c context.Context) (Facts, State, string) {
		ips, err := net.DefaultResolver.LookupIPAddr(c, opt.Host)
		if err != nil {
			state, code := classify(err)
			if state == Failed {
				code = "lookup_failed"
			}
			return Facts{}, state, code
		}
		addresses := []string{}
		for _, ip := range ips {
			addresses = append(addresses, ip.IP.String())
		}
		slices.Sort(addresses)
		addresses = slices.Compact(addresses)
		if len(addresses) == 0 {
			return Facts{}, Failed, "lookup_failed"
		}
		return Facts{Addresses: addresses}, Observed, ""
	})
	probe("dns_tailscale", func(c context.Context) (Facts, State, string) {
		if _, err := netip.ParseAddr(opt.Host); err == nil {
			return Facts{}, NotCollected, "not_requested"
		}
		kind := "A"
		if netip.MustParseAddr(opt.Address).Is6() {
			kind = "AAAA"
		}
		packet, _, err := lc.QueryDNS(c, opt.Host, kind)
		if err != nil {
			state, code := classify(err)
			return Facts{}, state, code
		}
		var msg dnsmessage.Message
		if err = msg.Unpack(packet); err != nil {
			return Facts{}, Failed, "probe_failed"
		}
		if msg.RCode != dnsmessage.RCodeSuccess {
			return Facts{}, Failed, "lookup_failed"
		}
		addresses := []string{}
		for _, answer := range msg.Answers {
			switch a := answer.Body.(type) {
			case *dnsmessage.AResource:
				addresses = append(addresses, netip.AddrFrom4(a.A).String())
			case *dnsmessage.AAAAResource:
				addresses = append(addresses, netip.AddrFrom16(a.AAAA).String())
			}
		}
		slices.Sort(addresses)
		addresses = slices.Compact(addresses)
		if len(addresses) == 0 {
			return Facts{}, Failed, "lookup_failed"
		}
		return Facts{Addresses: addresses}, Observed, ""
	})
	probe("peer", func(c context.Context) (Facts, State, string) {
		if opt.Role != "source" || opt.Router == "" {
			return Facts{}, NotCollected, "not_requested"
		}
		p, err := lc.Ping(c, netip.MustParseAddr(opt.Router), tailcfg.PingDisco)
		if err != nil {
			state, code := classify(err)
			return Facts{}, state, code
		}
		if p == nil || p.Err != "" {
			return Facts{}, Failed, "probe_failed"
		}
		path := "unknown"
		if p.Endpoint != "" {
			path = "direct"
		} else if p.PeerRelay != "" {
			path = "peer_relay"
		} else if p.DERPRegionID != 0 {
			path = "derp"
		}
		node := p.NodeIP
		if node == "" {
			node = p.IP
		}
		if node == "" {
			return Facts{}, Failed, "probe_failed"
		}
		return Facts{Node: node, Path: path}, Observed, ""
	})
	probe("tcp", func(c context.Context) (Facts, State, string) {
		d := net.Dialer{}
		conn, err := d.DialContext(c, "tcp", net.JoinHostPort(opt.Address, fmt.Sprint(opt.Port)))
		if err == nil {
			conn.Close()
			return Facts{TCP: "connected"}, Observed, ""
		}
		state, code := classify(err)
		result := "failed"
		if code == "refused" {
			result = "refused"
		}
		if state == TimedOut {
			result = "timeout"
		}
		if state == Denied {
			return Facts{}, state, code
		}
		return Facts{TCP: result}, state, code
	})
	probe("forwarding", func(c context.Context) (Facts, State, string) {
		if opt.Role != "router" {
			return Facts{}, NotCollected, "not_requested"
		}
		if runtime.GOOS != "linux" {
			return Facts{}, Unsupported, "unsupported"
		}
		path := "/proc/sys/net/ipv4/ip_forward"
		if netip.MustParseAddr(opt.Address).Is6() {
			path = "/proc/sys/net/ipv6/conf/all/forwarding"
		}
		data, err := os.ReadFile(path)
		if err != nil {
			state, code := classify(err)
			return Facts{}, state, code
		}
		value := strings.TrimSpace(string(data))
		if value != "0" && value != "1" {
			return Facts{}, Failed, "probe_failed"
		}
		enabled := value == "1"
		return Facts{Enabled: &enabled}, Observed, ""
	})
	b.End = time.Now().UTC()
	return b, b.Validate()
}

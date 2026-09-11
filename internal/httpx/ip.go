package httpx

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ProxyChecker decides which direct peers and X-Forwarded-For entries may
// be trusted when determining the client IP. The zero value (and nil)
// trusts nothing: the client IP is always the RemoteAddr peer.
type ProxyChecker struct {
	trusted []*net.IPNet
}

// ParseTrustedProxies parses CIDR strings (IPv4 or IPv6). A nil or empty
// list yields a checker that trusts nothing.
func ParseTrustedProxies(cidrs []string) (*ProxyChecker, error) {
	if len(cidrs) == 0 {
		return &ProxyChecker{}, nil
	}
	pc := &ProxyChecker{}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("httpx: bad trusted proxy CIDR %q: %w", c, err)
		}
		pc.trusted = append(pc.trusted, n)
	}
	return pc, nil
}

func (p *ProxyChecker) isTrusted(ip net.IP) bool {
	if p == nil {
		return false
	}
	for _, n := range p.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP extracts the real client IP from a request.
//
// X-Forwarded-For is only consulted when the direct peer (RemoteAddr) is a
// trusted proxy, which prevents clients that connect directly from
// spoofing their IP. Within XFF the rightmost entry added by an untrusted
// hop is the client: entries are walked from right to left while they are
// trusted proxies. If every entry is trusted the leftmost entry is used;
// without any usable XFF entry the peer address is returned.
func (p *ProxyChecker) ClientIP(r *http.Request) string {
	peer, _ := splitHostPort(r.RemoteAddr)
	peerIP := net.ParseIP(peer)
	if peerIP == nil || !p.isTrusted(peerIP) {
		return peer
	}

	var hops []net.IP
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(h, ",") {
			host, _ := splitHostPort(strings.TrimSpace(part))
			if ip := net.ParseIP(host); ip != nil {
				hops = append(hops, ip)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !p.isTrusted(hops[i]) {
			return hops[i].String()
		}
	}
	if len(hops) > 0 {
		return hops[0].String()
	}
	return peer
}

// splitHostPort splits "host:port" / "[v6]:port" / bare addresses,
// returning the host part.
func splitHostPort(s string) (string, error) {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h, nil
	}
	return s, nil
}

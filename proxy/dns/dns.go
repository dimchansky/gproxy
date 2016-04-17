package dns

import (
	"errors"
	"math/rand"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// Resolver represents a dns resolver
type Resolver struct {
	Servers    []string
	RetryTimes int
}

// New initializes DnsResolver.
func NewResolver(servers []string) *Resolver {
	for i := range servers {
		servers[i] += ":53"
	}

	return &Resolver{servers, len(servers) * 2}
}

// NewFromResolvConf initializes Resolver from resolv.conf like file.
func NewFromResolvConf(path string) (*Resolver, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &Resolver{}, errors.New("no such file or directory: " + path)
	}
	config, err := dns.ClientConfigFromFile(path)
	servers := []string{}
	for _, ipAddress := range config.Servers {
		servers = append(servers, ipAddress+":53")
	}
	return &Resolver{servers, len(servers) * 2}, err
}

// LookupHost returns IP addresses of provied host.
// In case of timeout retries query RetryTimes times.
func (r *Resolver) LookupHost(host string) ([]net.IP, error) {
	return r.lookupHost(host, r.RetryTimes)
}

func (r *Resolver) lookupHost(host string, triesLeft int) ([]net.IP, error) {
	fqdnHost := dns.Fqdn(host)
	dnsServer := r.Servers[rand.Intn(len(r.Servers))]

	c := dns.Client{Net: "tcp"}
	m := dns.Msg{}
	m.SetQuestion(fqdnHost, dns.TypeA)
	in, _, err := c.Exchange(&m, dnsServer)

	result := []net.IP{}

	if err != nil {
		if strings.HasSuffix(err.Error(), "i/o timeout") && triesLeft > 0 {
			triesLeft--
			return r.lookupHost(host, triesLeft)
		}
		return result, err
	}

	if in != nil && in.Rcode != dns.RcodeSuccess {
		return result, errors.New(dns.RcodeToString[in.Rcode])
	}

	for _, record := range in.Answer {
		if t, ok := record.(*dns.A); ok {
			result = append(result, t.A)
		}
	}
	return result, err
}

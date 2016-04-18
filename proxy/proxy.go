package proxy

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dimchansky/gproxy/proxy/dns"
	"github.com/valyala/fasthttp"
)

const (
	googleHTTPSProxyName = "proxy.googlezip.net"
	proxyHeaderName      = "Chrome-Proxy"
	authValue            = "ac4500dd3b7579186c1b0620614fdb1f7d61f944"
	chromeVersion        = "48.0.2564.116"
)

var (
	chromeVersionReg     = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)\.(\d+)`)
	chromeVersionSplited = chromeVersionReg.FindStringSubmatch(chromeVersion)
	googleDNS            = []string{"8.8.8.8", "8.8.4.4"}
)

func getLongInt() int {
	return int(math.Floor(rand.Float64() * 1000000000))
}

func authHeader() string {
	timestamp := time.Now().Unix()

	return fmt.Sprintf("ps=%v-%v-%v-%v, sid=%x, b=%v, p=%v, c=win",
		timestamp,
		getLongInt(),
		getLongInt(),
		getLongInt(),
		md5.Sum([]byte(fmt.Sprintf("%v%v%v", timestamp, authValue, timestamp))),
		chromeVersionSplited[3],
		chromeVersionSplited[4])
}

func addChromeProxyAuthHeader(req *fasthttp.Request) {
	req.Header.Set(proxyHeaderName, authHeader())
}

type Proxy struct {
	port        int
	dnsResolver *dns.Resolver
	proxyClient *fasthttp.HostClient
}

func New(port int) (*Proxy, error) {
	dnsResolver := dns.NewResolver(googleDNS)
	ips, err := dnsResolver.LookupHost(googleHTTPSProxyName)
	if err != nil {
		return nil, fmt.Errorf("Failed to lookup %s server IP address: %v", googleHTTPSProxyName, err)
	}

	proxyAddrs := make([]string, len(ips))
	for i, ip := range ips {
		proxyAddrs[i] = ip.String() + ":443"
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         googleHTTPSProxyName,
	}
	client := &fasthttp.HostClient{
		Addr:      strings.Join(proxyAddrs, ","),
		IsTLS:     true,
		TLSConfig: tlsConfig,
	}

	return &Proxy{port: port, dnsResolver: dnsResolver, proxyClient: client}, nil
}

func (p *Proxy) Listen() error {
	s := &fasthttp.Server{
		Handler:        p.requestHandler,
		ReadBufferSize: 16384,
	}
	addr := "127.0.0.1:" + strconv.Itoa(p.port)
	return s.ListenAndServe(addr)
}

func (p *Proxy) GetAutoConfigurationUrl() string {
	return fmt.Sprintf("http://127.0.0.1:%d/wpad.dat", p.port)
}

var (
	connectBytes    = []byte("CONNECT")
	wpadDatBytes    = []byte("/wpad.dat")
	faviconIcoBytes = []byte("/favicon.ico")
	slashBytes      = []byte("/")
)

func (p *Proxy) requestHandler(ctx *fasthttp.RequestCtx) {
	if bytes.Equal(ctx.Method(), connectBytes) {
		p.handleHTTPSProxy(ctx)
	} else {
		p.handleHTTP(ctx)
	}
}

func (p *Proxy) handleHTTP(ctx *fasthttp.RequestCtx) {
	requestURI := ctx.RequestURI()
	log.Printf("%s %s", string(ctx.Method()), string(requestURI))

	if bytes.HasPrefix(requestURI, slashBytes) {
		// non-proxy request
		if bytes.Equal(requestURI, wpadDatBytes) {
			p.handleProxyAutoConfiguration(ctx)
		} else if bytes.Equal(requestURI, faviconIcoBytes) {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
		} else {
			// redirect to proxy auto-configuration script
			ctx.RedirectBytes(wpadDatBytes, fasthttp.StatusFound)
		}
	} else {
		// proxy request
		p.handleHTTPProxy(ctx)
	}
}

func (p *Proxy) handleHTTPSProxy(ctx *fasthttp.RequestCtx) {
	hostPort := string(ctx.Host())

	log.Printf("%s %s", string(ctx.Method()), hostPort)

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		port = "443"
	}

	hostIPs, err := p.dnsResolver.LookupHost(host)
	if err != nil {
		log.Printf("dns: failed to resolve IP for host %v: %v", host, err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}

	if len(hostIPs) == 0 {
		log.Printf("dns: no IP resolved for %v", host)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}

	randomIP := hostIPs[rand.Intn(len(hostIPs))]
	randomIPStr := randomIP.String()

	hostConn, err := net.Dial("tcp", randomIPStr+":"+port)
	if err != nil {
		log.Printf("http: dial error: %v", err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}

	ctx.Hijack(func(clientConn net.Conn) {
		defer hostConn.Close()

		go func() {
			io.Copy(hostConn, clientConn)
		}()
		io.Copy(clientConn, hostConn)
	})

	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (p *Proxy) handleHTTPProxy(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	resp := &ctx.Response

	addChromeProxyAuthHeader(req)

	if err := p.proxyClient.Do(req, resp); err != nil {
		log.Printf("error occurred when proxying the request: %s", err)
	}
}

func (p *Proxy) handleProxyAutoConfiguration(ctx *fasthttp.RequestCtx) {
	localAddr := ctx.LocalAddr().(*net.TCPAddr)

	ctx.Response.Header.Set("Host", localAddr.IP.String())
	ctx.SetContentType("application/x-ns-proxy-autoconfig; charset=UTF-8")
	ctx.Response.Header.Set("Content-Disposition", "attachment; filename=\"wpad.dat\"")

	fmt.Fprintf(ctx, `function FindProxyForURL(url, host) {
  if (!isPlainHostName(host) && 
      !shExpMatch(host, '*.local') && 
      !isInNet(dnsResolve(host), '10.0.0.0', '255.0.0.0') && 
      !isInNet(dnsResolve(host), '172.16.0.0',  '255.240.0.0') && 
      !isInNet(dnsResolve(host), '192.168.0.0',  '255.255.0.0') && 
      !isInNet(dnsResolve(host), '127.0.0.0', '255.255.255.0') ) 
    return 'PROXY %s';
  return 'DIRECT';
}
`, localAddr.String())
}

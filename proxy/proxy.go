package proxy

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dimchansky/gproxy/proxy/dns"
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
	errorNoIPResolved    = errors.New("No IP resolved")
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

func addChromeProxyAuthHeader(r *http.Request) {
	r.Header.Add(proxyHeaderName, authHeader())
}

type Proxy struct {
	port        int
	dnsResolver *dns.Resolver

	// BufferPool optionally specifies a buffer pool to
	// get byte slices for use by io.CopyBuffer when
	// copying HTTP response bodies.
	BufferPool httputil.BufferPool
}

func New(port int) (*Proxy, error) {
	dnsResolver := dns.NewResolver(googleDNS)
	return &Proxy{port: port, dnsResolver: dnsResolver}, nil
}

func (p *Proxy) Listen() error {
	addr := "127.0.0.1:" + strconv.Itoa(p.port)
	return http.ListenAndServe(addr, http.HandlerFunc(p.requestHandler))
}

func (p *Proxy) GetAutoConfigurationUrl() string {
	return fmt.Sprintf("http://127.0.0.1:%d/wpad.dat", p.port)
}

func (p *Proxy) requestHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == "CONNECT" {
		p.handleHTTPSProxy(w, req)
	} else {
		p.handleHTTP(w, req)
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, req *http.Request) {
	log.Printf("%s %s", req.Method, req.URL)

	if !req.URL.IsAbs() {
		// non-proxy request
		if req.URL.Path == "/wpad.dat" {
			p.handleProxyAutoConfiguration(w, req)
		} else if req.URL.Path == "/favicon.ico" {
			w.WriteHeader(http.StatusNotFound)
		} else {
			// redirect to proxy auto-configuration script
			http.Redirect(w, req, "/wpad.dat", http.StatusFound)
		}
	} else {
		// proxy request
		p.handleHTTPProxy(w, req)
	}
}

func (p *Proxy) handleHTTPSProxy(w http.ResponseWriter, req *http.Request) {
	hostPort := req.Host

	log.Printf("%s %s", req.Method, hostPort)

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		port = "443"
	}

	var hostIPAddrStr string
	if ip := net.ParseIP(host); ip == nil {
		// it's not an IP address
		hostIPAddr, err := p.resolveIPAddress(host)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		hostIPAddrStr = hostIPAddr.String()
	} else {
		hostIPAddrStr = host
	}

	hostConn, err := net.Dial("tcp", net.JoinHostPort(hostIPAddrStr, port))
	if err != nil {
		log.Printf("http: dial error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer hostConn.Close()

	hij, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Proxy does not support hijacking")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	clientConn, _, e := hij.Hijack()
	if err != nil {
		log.Printf("Cannot hijack connection: %v", e)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

	go func() {
		p.copyBuffer(hostConn, clientConn)
	}()
	p.copyBuffer(clientConn, hostConn)
}

func (p *Proxy) handleHTTPProxy(w http.ResponseWriter, req *http.Request) {
	outreq := new(http.Request)
	*outreq = *req // includes shallow copies of maps, but okay

	config := tls.Config{InsecureSkipVerify: false, ServerName: googleHTTPSProxyName}

	proxyIPAddr, err := p.resolveIPAddress(googleHTTPSProxyName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	proxyAddr := proxyIPAddr.String() + ":443"

	googleProxyConn, err := tls.Dial("tcp", proxyAddr, &config)
	if err != nil {
		log.Printf("tls: dial error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer googleProxyConn.Close()

	outreq.Proto = "HTTP/1.1"
	outreq.ProtoMajor = 1
	outreq.ProtoMinor = 1
	outreq.Close = false
	addChromeProxyAuthHeader(outreq)

	outreq.Write(googleProxyConn)

	br := bufio.NewReader(googleProxyConn)
	resp, err := http.ReadResponse(br, outreq)
	if err != nil {
		log.Printf("http: read response error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	copyHeader(w.Header(), resp.Header)

	if len(resp.Trailer) > 0 {
		var trailerKeys []string
		for k := range resp.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		w.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	w.WriteHeader(resp.StatusCode)
	if len(resp.Trailer) > 0 {
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
	}

	p.copyBuffer(w, resp.Body)
	resp.Body.Close()
	copyHeader(w.Header(), resp.Trailer)
}

func (p *Proxy) resolveIPAddress(host string) (net.IP, error) {
	hostIPs, err := p.dnsResolver.LookupHost(host)
	if err != nil {
		log.Printf("dns: failed to resolve IP for host %v: %v", host, err)
		return nil, err
	}

	if len(hostIPs) == 0 {
		log.Printf("dns: no IP resolved for host %v", host)
		return nil, errorNoIPResolved
	}

	randomIP := hostIPs[rand.Intn(len(hostIPs))]
	return randomIP, nil
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (p *Proxy) copyBuffer(dst io.Writer, src io.Reader) {
	var buf []byte
	if p.BufferPool != nil {
		buf = p.BufferPool.Get()
	}
	io.CopyBuffer(dst, src, buf)
	if p.BufferPool != nil {
		p.BufferPool.Put(buf)
	}
}

func (p *Proxy) handleProxyAutoConfiguration(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Host", "127.0.0.1")
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig; charset=UTF-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"wpad.dat\"")

	fmt.Fprintf(w, `function FindProxyForURL(url, host) {
  if (!isPlainHostName(host) && 
      !shExpMatch(host, '*.local') && 
      !isInNet(dnsResolve(host), '10.0.0.0', '255.0.0.0') && 
      !isInNet(dnsResolve(host), '172.16.0.0',  '255.240.0.0') && 
      !isInNet(dnsResolve(host), '192.168.0.0',  '255.255.0.0') && 
      !isInNet(dnsResolve(host), '127.0.0.0', '255.255.255.0') ) 
    return 'PROXY %v:%d';
  return 'DIRECT';
}
`, "127.0.0.1", p.port)
}

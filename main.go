package main

import (
	"flag"
	"log"

	"github.com/dimchansky/gproxy/proxy"
)

var (
	proxyPort = flag.Int("port", 8080, "Local proxy port to listen to.")
)

func main() {
	flag.Parse()

	proxy, err := proxy.New(*proxyPort)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Proxy Auto-Configuration: " + proxy.GetAutoConfigurationUrl())
	log.Fatal(proxy.Listen())
}

package main

import (
	"fmt"
	"golang.org/x/net/http2"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"log"
	"io/ioutil"
)

var enableLogging = true

func main() {
	if !enableLogging {
		fmt.Printf("Logging is disabled")
		log.SetOutput(ioutil.Discard)
	}

	H2CServerPrior()
}

// This server only supports "H2C prior knowledge".
// You can add standard HTTP/2 support by adding a TLS config.
func H2CServerPrior() {
	client := http.Client{
		Transport: &http2.Transport{
			// So http2.Transport doesn't complain the URL scheme isn't 'https'
			AllowHTTP: true,
			// Pretend we are dialing a TLS endpoint. (Note, we ignore the passed tls.Config)
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
	 	},
	}
	server := http2.Server{}
	imsi := 2089300000000
  l, err := net.Listen("tcp", "0.0.0.0:80")
  CheckErr(err, "while listening")

	log.Printf("Listening [0.0.0.0:80]...\n")
	for {
		conn, err := l.Accept()
		CheckErr(err, "during accept")

    imsi = imsi + 1
		server.ServeConn(conn, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.Printf("New Connection: %+v\n", r)
        RunRegTrans(strconv.Itoa(imsi))
			}),
		})
	}
}

// Check for Error
func CheckErr(err error, msg string) {
	if err == nil {
		return
	}
	log.Fatalf("ERROR: %s: %s\n", msg, err)
}

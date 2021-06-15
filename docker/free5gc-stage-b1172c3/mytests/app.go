package main

import (
  "test"
  "golang.org/x/net/http2"
	"crypto/tls"
	"net"
	"net/http"
  "github.com/free5gc/ngap"
  "github.com/free5gc/ngap/ngapType"
	"strconv"
	"log"
	"fmt"
	"io/ioutil"
	"git.cs.nctu.edu.tw/calee/sctp"
)

const ranN2Ipv4Addr string = "10.244.1.3"
const amfN2Ipv4Addr string = "10.244.1.2"
const ranN3Ipv4Addr string = "10.244.1.3"
const upfN3Ipv4Addr string = "10.244.1.8"
var enableLogging = true

func main() {
	if !enableLogging {
	        fmt.Printf("Logging is disabled")
	        log.SetOutput(ioutil.Discard)
	}

	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	test.CheckErr(err, "ConnectToAmf")

	// RAN connect to UPF
	_, err = test.ConnectToUpf(ranN3Ipv4Addr, upfN3Ipv4Addr, 2152, 2152)
	test.CheckErr(err, "ConnectToUpf")

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	test.CheckErr(err, "GetNGSetupRequest")
	_, err = conn.Write(sendMsg)
	test.CheckErr(err, "Write(sendMsg)")

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	test.CheckErr(err, "Read(recvMsg)")
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	test.CheckErr(err, "ngap.Decoder")
	if ngapPdu.Present != ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value != ngapType.ProcedureCodeNGSetup {
		log.Fatalf("No NGSetupResponse received.")
	}

	H2CServerPrior(conn, ranN3Ipv4Addr)

}

func H2CServerPrior(AmfConn *sctp.SCTPConn, ranN3Ipv4Addr string) {
	_ = http.Client{
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
	
	l, err := net.Listen("tcp", "0.0.0.0:80")
	test.CheckErr(err, "while listening")

	log.Printf("Listening [0.0.0.0:80]...\n")
	imsi := 2089300000000
	ueCount := 0
	for {
		conn, err := l.Accept()
		test.CheckErr(err, "during accept")

		imsi = imsi + 1
		ueCount = ueCount + 1

		server.ServeConn(conn, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("New Connection: %+v\n", r)
			test.RunRegTrans(AmfConn, strconv.Itoa(imsi), ranN3Ipv4Addr, ueCount)
			}),
		})
	}
}

package main

import (
        "test"
        "github.com/free5gc/ngap"
        "github.com/free5gc/ngap/ngapType"
	"strconv"
	"log"
	"fmt"
	"io/ioutil"
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
	
	imsi := 2089300000000
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

	for i := 0; i < 1; i++ {
		fmt.Printf("Loop %d", i)
		fmt.Println("")
		test.RunRegTrans(conn, strconv.Itoa(imsi), ranN3Ipv4Addr, i)
	}

}

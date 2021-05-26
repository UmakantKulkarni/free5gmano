package main

import (
				"test"
				"testing"
        "time"
        "net"
        "encoding/hex"
				"github.com/stretchr/testify/assert"
        "github.com/stretchr/testify/require"
				"github.com/free5gc/CommonConsumerTestData/UDM/TestGenAuthData"
				"github.com/free5gc/nas"
				"github.com/free5gc/nas/nasMessage"
				"github.com/free5gc/nas/nasTestpacket"
				"github.com/free5gc/nas/nasType"
				"github.com/free5gc/nas/security"
				"github.com/free5gc/ngap"
				"github.com/free5gc/ngap/ngapType"
				"github.com/free5gc/openapi/models"
        "golang.org/x/net/icmp"
	      "golang.org/x/net/ipv4"
)

const ranN2Ipv4Addr string = "10.244.2.46"
const amfN2Ipv4Addr string = "10.244.1.34"
const ranN3Ipv4Addr string = "10.244.2.46"
const upfN3Ipv4Addr string = "10.244.2.41"

// Registration

func main() {
	var t *testing.T
  var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)

	// RAN connect to UPF
	upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, upfN3Ipv4Addr, 2152, 2152)
	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2)
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	// insert UE data to MongoDB

	servingPlmnId := "20893"
	test.InsertAuthSubscriptionToMongoDB(ue.Supi, ue.AuthenticationSubs)
	getData := test.GetAuthSubscriptionFromMongoDB(ue.Supi)
	assert.NotNil(t, getData)
	{
		amData := test.GetAccessAndMobilitySubscriptionData()
		test.InsertAccessAndMobilitySubscriptionDataToMongoDB(ue.Supi, amData, servingPlmnId)
		getData := test.GetAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smfSelData := test.GetSmfSelectionSubscriptionData()
		test.InsertSmfSelectionSubscriptionDataToMongoDB(ue.Supi, smfSelData, servingPlmnId)
		getData := test.GetSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smSelData := test.GetSessionManagementSubscriptionData()
		test.InsertSessionManagementSubscriptionDataToMongoDB(ue.Supi, servingPlmnId, smSelData)
		getData := test.GetSessionManagementDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		amPolicyData := test.GetAmPolicyData()
		test.InsertAmPolicyDataToMongoDB(ue.Supi, amPolicyData)
		getData := test.GetAmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}
	{
		smPolicyData := test.GetSmPolicyData()
		test.InsertSmPolicyDataToMongoDB(ue.Supi, smPolicyData)
		getData := test.GetSmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received.")

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(100 * time.Millisecond)
	// send GetPduSessionEstablishmentRequest Msg

	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "010203",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePDUSessionResourceSetup,
		"No PDUSessionResourceSetup received.")

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait 1s
	time.Sleep(1 * time.Second)

	// Send the dummy packet
	// ping IP(tunnel IP) from 60.60.0.2(127.0.0.1) to 60.60.0.20(127.0.0.8)
	gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
	assert.Nil(t, err)
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP("60.60.0.1").To4(),
		Dst:      net.ParseIP("60.60.0.101").To4(),
		ID:       1,
	}
	checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt := append(gtpHdr, v4HdrBuf...)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := m.Marshal(nil)
	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn.Write(append(tt, b...))
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	//NfTerminate()
}

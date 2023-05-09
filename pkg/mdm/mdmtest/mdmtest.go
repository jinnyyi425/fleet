package mdmtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/pkg/fleethttp"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/uuid"
	"github.com/groob/plist"
	micromdm "github.com/micromdm/micromdm/mdm/mdm"
	"github.com/micromdm/nanomdm/mdm"
	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/micromdm/scep/v2/cryptoutil/x509util"
	"github.com/micromdm/scep/v2/scep"
	"go.mozilla.org/pkcs7"
)

type TestDevice struct {
	UUID   string
	Serial string
	Model  string

	fleetServerURL string
	debug          bool
	desktopToken   string

	EnrollInfo EnrollInfo
	dep        bool

	scepCert *x509.Certificate
	scepKey  *rsa.PrivateKey
}

func NewTestDevice(serverURL string, desktopToken string, debug bool) *TestDevice {
	return &TestDevice{
		UUID:   strings.ToUpper(uuid.New().String()),
		Serial: randSerial(),
		Model:  "MacBookPro16,1",

		fleetServerURL: serverURL,
		desktopToken:   desktopToken,
		dep:            false,
		debug:          debug,
	}
}

type EnrollInfo struct {
	SCEPChallenge string
	SCEPURL       string
	MDMURL        string
	APNSTopic     string
}

func NewDEPTestDevice(enrollInfo EnrollInfo, debug bool) *TestDevice {
	return &TestDevice{
		UUID:       strings.ToUpper(uuid.New().String()),
		Serial:     randSerial(),
		EnrollInfo: enrollInfo,
		Model:      "MacBookPro16,1",

		dep:   true,
		debug: debug,
	}
}

func (d *TestDevice) Enroll() error {
	if !d.dep {
		if err := d.GetEnrollmentProfile(); err != nil {
			return fmt.Errorf("get enrollment profile: %w", err)
		}
	}
	if err := d.SCEPEnroll(); err != nil {
		return fmt.Errorf("scep enroll: %w", err)
	}
	if err := d.Authenticate(); err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	if err := d.TokenUpdate(); err != nil {
		return fmt.Errorf("token update: %w", err)
	}
	return nil
}

func (d *TestDevice) GetEnrollmentProfile() error {
	c := fleethttp.NewClient()
	request, err := http.NewRequest("GET",
		d.fleetServerURL+"/api/latest/fleet/device/"+d.desktopToken+"/mdm/apple/manual_enrollment_profile",
		nil,
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	response, err := c.Do(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("request error: %d, %s", response.StatusCode, response.Status)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if err := response.Body.Close(); err != nil {
		return fmt.Errorf("close body: %w", err)
	}
	enrollInfo, err := ParseEnrollmentProfile(body)
	if err != nil {
		return fmt.Errorf("parse enrollment profile: %w", err)
	}
	d.EnrollInfo = *enrollInfo

	return nil
}

func (d *TestDevice) SCEPEnroll() error {
	ctx := context.Background()

	logger := kitlog.NewJSONLogger(os.Stdout)
	if d.debug {
		logger = level.NewFilter(logger, level.AllowDebug())
	}
	client, err := scepclient.New(d.EnrollInfo.SCEPURL, logger)
	if err != nil {
		return fmt.Errorf("scep client: %w", err)
	}

	// (1). Get the CA certificate from the SCEP server.
	resp, _, err := client.GetCACert(ctx, "")
	if err != nil {
		return fmt.Errorf("get CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificates(resp)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	// (2). Generate RSA key pair.
	devicePrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA private key: %w", err)
	}

	// (3). Generate CSR.
	cn := fmt.Sprintf("fleet-testdevice-%s", d.UUID)
	csrTemplate := x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   cn,
				Organization: []string{"fleet-organization"},
			},
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		ChallengePassword: d.EnrollInfo.SCEPChallenge,
	}
	csrDerBytes, err := x509util.CreateCertificateRequest(rand.Reader, &csrTemplate, devicePrivateKey)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDerBytes)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}

	// (4). SCEP requires a certificate for client authentication. We generate a new one
	// that uses the same CommonName and Key that we are trying to have signed.
	//
	// From RFC-8894:
	// If the client does not have an appropriate existing certificate, then a locally generated
	// self-signed certificate MUST be used. The keyUsage extension in the certificate MUST indicate that
	// it is valid for digitalSignature and keyEncipherment (if available). The self-signed certificate
	// SHOULD use the same subject name and key as in the PKCS #10 request.
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	certSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("generate cert serial number: %w", err)
	}
	deviceCertificateTemplate := x509.Certificate{
		SerialNumber: certSerialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: csr.Subject.Organization,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	deviceCertificateDerBytes, err := x509.CreateCertificate(
		rand.Reader,
		&deviceCertificateTemplate,
		&deviceCertificateTemplate,
		&devicePrivateKey.PublicKey,
		devicePrivateKey,
	)
	if err != nil {
		return fmt.Errorf("create device certificate: %w", err)
	}
	deviceCertificateForRequest, err := x509.ParseCertificate(deviceCertificateDerBytes)
	if err != nil {
		return fmt.Errorf("parse device certificate: %w", err)
	}

	// (5). Send the PKCSReq message to the SCEP server.
	pkiMsgReq := &scep.PKIMessage{
		MessageType: scep.PKCSReq,
		Recipients:  caCert,
		SignerKey:   devicePrivateKey,
		SignerCert:  deviceCertificateForRequest,
		CSRReqMessage: &scep.CSRReqMessage{
			ChallengePassword: d.EnrollInfo.SCEPChallenge,
		},
	}
	msg, err := scep.NewCSRRequest(csr, pkiMsgReq, scep.WithLogger(logger))
	if err != nil {
		return fmt.Errorf("create CSR request: %w", err)
	}
	respBytes, err := client.PKIOperation(ctx, msg.Raw)
	if err != nil {
		return fmt.Errorf("do CSR request: %w", err)
	}
	pkiMsgResp, err := scep.ParsePKIMessage(respBytes, scep.WithLogger(logger), scep.WithCACerts(msg.Recipients))
	if err != nil {
		return fmt.Errorf("parse PKIMessage response: %w", err)
	}
	if pkiMsgResp.PKIStatus != scep.SUCCESS {
		return fmt.Errorf("PKIMessage CSR request failed with code: %s, fail info: %s", pkiMsgResp.PKIStatus, pkiMsgResp.FailInfo)
	}
	if err := pkiMsgResp.DecryptPKIEnvelope(deviceCertificateForRequest, devicePrivateKey); err != nil {
		return fmt.Errorf("decrypt PKI envelope: %w", err)
	}

	// (6). Finally, set the signed certificate returned from the server as the device certificate and key.
	d.scepCert = pkiMsgResp.CertRepMessage.Certificate
	d.scepKey = devicePrivateKey

	return nil
}

func (d *TestDevice) Authenticate() error {
	payload := map[string]any{
		"MessageType":  "Authenticate",
		"UDID":         d.UUID,
		"Model":        d.Model,
		"DeviceName":   "testdevice" + d.Serial,
		"Topic":        "com.apple.mgmt.External." + d.UUID,
		"EnrollmentID": "testenrollmentid-" + d.UUID,
		"SerialNumber": d.Serial,
	}
	_, err := d.request("application/x-apple-aspen-mdm-checkin", payload)
	return err
}

func (d *TestDevice) TokenUpdate() error {
	payload := map[string]any{
		"MessageType":  "TokenUpdate",
		"UDID":         d.UUID,
		"Topic":        "com.apple.mgmt.External." + d.UUID,
		"EnrollmentID": "testenrollmentid-" + d.UUID,
		"NotOnConsole": "false",
		"PushMagic":    "pushmagic" + d.Serial,
		"Token":        []byte("token" + d.Serial),
	}
	_, err := d.request("application/x-apple-aspen-mdm-checkin", payload)
	return err
}

func (d *TestDevice) Checkout() error {
	payload := map[string]any{
		"MessageType":  "CheckOut",
		"Topic":        "com.apple.mgmt.External." + d.UUID,
		"UDID":         d.UUID,
		"EnrollmentID": "testenrollmentid-" + d.UUID,
	}
	_, err := d.request("application/x-apple-aspen-mdm-checkin", payload)
	return err
}

// Idle sends a Idle request to the MDM server.
//
// Devices send an Idle status to signal the server that they're ready to
// receive commands. The server can signal back with either a command to run
// or an empty (nil, nil) response body to end the communication.
func (d *TestDevice) Idle() (*micromdm.CommandPayload, error) {
	payload := map[string]any{
		"Status":       "Idle",
		"Topic":        "com.apple.mgmt.External." + d.UUID,
		"UDID":         d.UUID,
		"EnrollmentID": "testenrollmentid-" + d.UUID,
	}
	return d.sendAndDecodeCommandResponse(payload)
}

func (d *TestDevice) Acknowledge(cmdUUID string) (*micromdm.CommandPayload, error) {
	payload := map[string]any{
		"Status":       "Acknowledged",
		"Topic":        "com.apple.mgmt.External." + d.UUID,
		"UDID":         d.UUID,
		"EnrollmentID": "testenrollmentid-" + d.UUID,
		"CommandUUID":  cmdUUID,
	}
	return d.sendAndDecodeCommandResponse(payload)
}

func (d *TestDevice) Err(cmdUUID string, errChain []mdm.ErrorChain) (*micromdm.CommandPayload, error) {
	payload := map[string]any{
		"Status":       "Error",
		"Topic":        "com.apple.mgmt.External." + d.UUID,
		"UDID":         d.UUID,
		"EnrollmentID": "testenrollmentid-" + d.UUID,
		"CommandUUID":  cmdUUID,
		"ErrorChain":   errChain,
	}
	return d.sendAndDecodeCommandResponse(payload)
}

func (d *TestDevice) sendAndDecodeCommandResponse(payload map[string]any) (*micromdm.CommandPayload, error) {
	res, err := d.request("", payload)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}
	if res.ContentLength == 0 {
		if d.debug {
			fmt.Printf("response: no commands returned\n")
		}
		return nil, nil
	}
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if d.debug {
		fmt.Printf("response: %s", raw)
	}
	if err = res.Body.Close(); err != nil {
		return nil, fmt.Errorf("close response body: %w", err)
	}
	cmd, err := mdm.DecodeCommand(raw)
	if err != nil {
		return nil, fmt.Errorf("decode command: %w", err)
	}
	var p micromdm.CommandPayload
	err = plist.Unmarshal(cmd.Raw, &p)
	if err != nil {
		return nil, fmt.Errorf("unmarshal command payload: %w", err)
	}
	return &p, nil
}

func (d *TestDevice) request(contentType string, payload map[string]any) (*http.Response, error) {
	body, err := plist.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	signedData, err := pkcs7.NewSignedData(body)
	if err != nil {
		return nil, fmt.Errorf("create signed data: %w", err)
	}
	err = signedData.AddSigner(d.scepCert, d.scepKey, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, fmt.Errorf("add signer: %w", err)
	}
	sig, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("finish signing: %w", err)
	}

	if d.debug {
		fmt.Printf("request: %s", body)
	}
	request, err := http.NewRequest("POST", d.EnrollInfo.MDMURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Mdm-Signature", base64.StdEncoding.EncodeToString(sig))
	response, err := fleethttp.NewClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request error: %d, %s", response.StatusCode, response.Status)
	}
	return response, nil
}

// numbers plus capital letters without I, L, O for readability
const serialLetters = "0123456789ABCDEFGHJKMNPQRSTUVWXYZ"

func randSerial() string {
	b := make([]byte, 12)
	for i := range b {
		//nolint:gosec // not used for crypto, only to generate random serial for testing
		b[i] = serialLetters[mrand.Intn(len(serialLetters))]
	}
	return string(b)
}

// ParseEnrollmentProfile parses the enrollment profile and returns the parsed
// information as EnrollInfo.
func ParseEnrollmentProfile(mobileConfig []byte) (*EnrollInfo, error) {
	var enrollmentProfile struct {
		PayloadContent []map[string]interface{} `plist:"PayloadContent"`
	}
	if err := plist.Unmarshal(mobileConfig, &enrollmentProfile); err != nil {
		return nil, fmt.Errorf("unmarshal enrollment profile: %w", err)
	}
	payloadContent := enrollmentProfile.PayloadContent[0]["PayloadContent"].(map[string]interface{})

	scepChallenge, ok := payloadContent["Challenge"].(string)
	if !ok || scepChallenge == "" {
		return nil, errors.New("SCEP Challenge field not found")
	}
	scepURL, ok := payloadContent["URL"].(string)
	if !ok || scepURL == "" {
		return nil, errors.New("SCEP URL field not found")
	}
	mdmURL, ok := enrollmentProfile.PayloadContent[1]["ServerURL"].(string)
	if !ok || mdmURL == "" {
		return nil, errors.New("MDM ServerURL field not found")
	}
	apnsTopic, ok := enrollmentProfile.PayloadContent[1]["Topic"].(string)
	if !ok || apnsTopic == "" {
		return nil, errors.New("MDM Topic field not found")
	}
	return &EnrollInfo{
		SCEPChallenge: scepChallenge,
		SCEPURL:       scepURL,
		MDMURL:        mdmURL,
		APNSTopic:     apnsTopic,
	}, nil
}

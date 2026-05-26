package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"
)

type AddOn struct {
	Code      string `json:"code"`
	EndDate   string `json:"end_date"`
	ID        string `json:"id"`
	Owner     string `json:"owner"`
	StartDate string `json:"start_date"`
}

type License struct {
	AddOns         []AddOn `json:"add_ons"`
	Description    string  `json:"description"`
	EditionID      string  `json:"edition_id"`
	EndDate        string  `json:"end_date"`
	ID             string  `json:"id"`
	IssuedOn       string  `json:"issued_on"`
	LicenseType    string  `json:"license_type"`
	Owner          string  `json:"owner"`
	ProductID      string  `json:"product_id"`
	ProductVersion string  `json:"product_version"`
	Seats          int     `json:"seats"`
	StartDate      string  `json:"start_date"`
}

type Payload struct {
	Email    string    `json:"email"`
	Licenses []License `json:"licenses"`
	Name     string    `json:"name"`
}

type Hexlic struct {
	Header    map[string]int `json:"header"`
	Payload   Payload        `json:"payload"`
	Signature string         `json:"signature"`
}

func loadOrGenerateKey() *rsa.PrivateKey {
	keyFile := "private_key.pem"
	if data, err := os.ReadFile(keyFile); err == nil {
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "RSA PRIVATE KEY" {
			privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				slog.Info("loaded existing key", "file", keyFile)
				return privKey
			}
		}
	}

	slog.Info("gen new rsa keypair...")
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		slog.Error("failed to generate key!", "error", err)
		os.Exit(1)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	pemFile, err := os.Create(keyFile)
	if err == nil {
		pem.Encode(pemFile, pemBlock)
		pemFile.Close()
		slog.Info("saved new rsa key", "file", keyFile)
	} else {
		slog.Warn("whops, failed to save key to file", "error", err)
	}

	return privKey
}

func main() {
	privKey := loadOrGenerateKey()

	nBytes := privKey.N.Bytes()
	if len(nBytes) < 128 {
		pad := make([]byte, 128-len(nBytes))
		nBytes = append(pad, nBytes...)
	}

	// n is stored in libida as le (at least in dylib)
	leN := make([]byte, 128)
	for i := 0; i < 128; i++ {
		leN[i] = nBytes[127-i]
	}

	slog.Info("libida patch info",
		"pub_key", fmt.Sprintf("%x", leN),
		"pub_exp", privKey.E,
	)

	// payload
	now := time.Now()
	issueDate := now.Format("2006-01-02 15:04:05")
	startDate := now.Format("2006-01-02")
	endDate := now.AddDate(10 /*years*/, 0, 0).Format("2006-01-02")

	payload := Payload{
		Email: "lain@iwakura.page",
		Name:  "lain iwakurwa",
		Licenses: []License{
			{
				ID:             "43-0000-FFFF-37",
				Owner:          "lain iwakura",
				ProductID:      "IDAPRO",
				ProductVersion: "9.3",
				EditionID:      "ida-pro",
				Description:    "IDA Pro",
				StartDate:      startDate,
				EndDate:        endDate,
				IssuedOn:       issueDate,
				LicenseType:    "named",
				Seats:          1,
				AddOns: []AddOn{
					{Code: "HEXCX64", ID: "48-1337-B00B-01", Owner: "67-0000-FFFF-69", StartDate: startDate, EndDate: endDate},
					{Code: "HEXCX86", ID: "48-1337-B00B-02", Owner: "42-0000-FFFF-76", StartDate: startDate, EndDate: endDate},
					{Code: "HEXX64", ID: "48-1337-B00B-06", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "HEXX86", ID: "48-1337-B00B-07", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "HEXARM64", ID: "48-1337-B00B-03", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "HEXARM", ID: "48-1337-B00B-08", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "HEXMIPS", ID: "48-1337-B00B-09", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "HEXMIPS64", ID: "48-1337-B00B-10", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "HEXAVR", ID: "48-1337-B00B-11", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "HEXMAC", ID: "48-1337-B00B-12", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "HEXRVD", ID: "48-1337-B00B-13", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "HEXRISCV", ID: "48-1337-B00B-14", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "HEXRISCV64", ID: "48-1337-B00B-15", Owner: "B0-0B55-0000-88", StartDate: startDate, EndDate: endDate},
					{Code: "LUMINA", ID: "48-1337-B00B-04", Owner: "B1-0000-FFFF-33", StartDate: startDate, EndDate: endDate},
					{Code: "TEAMS", ID: "48-1337-B00B-05", Owner: "14-0000-FFFF-88", StartDate: startDate, EndDate: endDate},
				},
			},
		},
	}

	wrapperObj := map[string]interface{}{
		"payload": payload,
	}

	tempBytes, _ := json.Marshal(wrapperObj)

	// unmarshal into a generic map
	var wrapper map[string]interface{}
	err := json.Unmarshal(tempBytes, &wrapper)
	if err != nil {
		slog.Error("failed to unmarshal wrapper", "error", err)
		os.Exit(1)
	}

	payloadBytes, err := json.Marshal(wrapper)
	if err != nil {
		slog.Error("failed to marshal sorted payload", "error", err)
		os.Exit(1)
	}

	hash := sha256.Sum256(payloadBytes)

	// idas rsa signature padding for hexlic (be repres):
	// total length must be exactly 127 bytes to bypass length checks
	// byte 0..31: random padding (byte 0 MUST NOT be 0x00)
	// byte 32..63: sha256 hash of the json payload
	// byte 64..126: 0x00 padding

	beBlock := make([]byte, 127)
	rand.Read(beBlock[0:32])
	for beBlock[0] == 0 {
		rand.Read(beBlock[0:1])
	}

	copy(beBlock[32:64], hash[:])

	m := new(big.Int).SetBytes(beBlock)
	s := new(big.Int).Exp(m, privKey.D, privKey.N)

	sigBytes := s.Bytes()
	if len(sigBytes) < 128 {
		pad := make([]byte, 128-len(sigBytes))
		sigBytes = append(pad, sigBytes...)
	}

	// ida parses the signature hex string as a le byte array
	// we need to reverse our be signature before writing to json
	sigBytesLe := make([]byte, 128)
	for i := 0; i < 128; i++ {
		sigBytesLe[i] = sigBytes[127-i]
	}

	// nd here we go
	hexlic := Hexlic{
		Header:    map[string]int{"version": 1},
		Payload:   payload,
		Signature: fmt.Sprintf("%X", sigBytesLe),
	}

	finalBytes, _ := json.MarshalIndent(hexlic, "", "  ")
	err = os.WriteFile("ida.hexlic", finalBytes, 0644)
	if err != nil {
		slog.Error("whops, failed to write file", "error", err)
		os.Exit(1)
	}

	slog.Info("gen ida.hexlic done!")
}

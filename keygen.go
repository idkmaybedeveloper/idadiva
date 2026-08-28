package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"
)

const (
	cModulusHex = "3f0307607fed562fd5a163adc40fcc603373caa28414e64cdc4552a555b13ad" +
		"4b3ad0a812800a03195300fd71634b90edb0d69ea710efebb2b0b9e72da2effb1" +
		"49de70bcbfa94b86af01ce455dbbd5fa987207651c7b60c2e4cafd0654188d98c" +
		"30f64dc084d8547f0ac32db91124af82b3b15bf922a31f1d5e332f27615cea7"

	privateKeyHex = "8b3f5fdfad7f87239734c530e2ecebeb4fa48d79518756c15fd54636801cf7e" +
		"a6367100566bf8b52b16bec05258d8426ea94c15841ab2d37802c07349df4c208" +
		"584e86d25a6bfb82966cb2ddcd3d654e9994e814ca470577362a937cc984e404a" +
		"0b68d173aab3180130118e1b03ed209a9d8757560a85a3c9b0d3380e7907c4f"

	padKeyHex = "e2a7c300dfcc777f89b57500d8151c7fb1d97b3f9f170393311234ceeb9e377a" +
		"e2a7c300dfcc777f89b57500d8151c7fb1d97b3f9f170393311234ceeb9e377a" +
		"e2a7c300dfcc777f89b57500d8151c7fb1d97b3f9f170393311234ceeb9e377a" +
		"e2a7c300dfcc777f89b57500d8151c7fb1d97b3f9f170393311234ceeb9e37"
)

type AddOn struct {
	Code      string `json:"code"`
	EndDate   string `json:"end_date"`
	ID        string `json:"id"`
	Owner     string `json:"owner"`
	StartDate string `json:"start_date"`
}

type License struct {
	AddOns         []AddOn       `json:"add_ons"`
	Description    string        `json:"description"`
	EditionID      string        `json:"edition_id"`
	EndDate        string        `json:"end_date"`
	Features       []interface{} `json:"features"`
	ID             string        `json:"id"`
	IssuedOn       string        `json:"issued_on"`
	LicenseType    string        `json:"license_type"`
	Owner          string        `json:"owner"`
	Product        string        `json:"product"`
	ProductID      string        `json:"product_id"`
	ProductVersion string        `json:"product_version"`
	Seats          int           `json:"seats"`
	StartDate      string        `json:"start_date"`
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

func leHexToBigInt(hexStr string) *big.Int {
	b, _ := hex.DecodeString(hexStr)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return new(big.Int).SetBytes(b)
}

func main() {
	n := leHexToBigInt(cModulusHex)
	d := leHexToBigInt(privateKeyHex)
	padKey, _ := hex.DecodeString(padKeyHex)

	now := time.Now()
	issueDate := now.Format("2006-01-02 15:04:05")
	startDate := "2020-01-01 00:00:00"
	endDate := now.AddDate(67, 0, 0).Format("2006-01-02") + " 00:00:00"

	licID := "43-0000-FFFF-37"

	addons := []string{
		"LUMINA", "TEAMS", "HEXX86", "HEXX64", "HEXARM", "HEXARM64",
		"HEXMIPS", "HEXMIPS64", "HEXPPC", "HEXPPC64", "HEXRV", "HEXRV64",
		"HEXARC", "HEXARC64", "HEXV850", "HEXDALVIK",
	}
	addOnList := make([]AddOn, len(addons))
	for i, code := range addons {
		addOnList[i] = AddOn{
			Code:      code,
			ID:        fmt.Sprintf("48-1337-B00B-%02d", i+1),
			Owner:     licID,
			StartDate: startDate,
			EndDate:   endDate,
		}
	}

	payload := Payload{
		Email: "lain@iwakura.page",
		Name:  "lain iwakura",
		Licenses: []License{
			{
				ID:             licID,
				Owner:          "lain iwakura",
				Product:        "IDA",
				ProductID:      "IDAPRO",
				ProductVersion: "9.4",
				EditionID:      "ida-pro",
				Description:    "IDA Pro",
				StartDate:      startDate,
				EndDate:        endDate,
				IssuedOn:       issueDate,
				LicenseType:    "named",
				Seats:          67,
				Features:       []interface{}{},
				AddOns:         addOnList,
			},
		},
	}

	// sort({payload}) - marshal struct -> unmarshal to generic map -> re-marshal (keys sorted)
	wrapperObj := map[string]interface{}{"payload": payload}
	tempBytes, _ := json.Marshal(wrapperObj)
	var wrapper map[string]interface{}
	if err := json.Unmarshal(tempBytes, &wrapper); err != nil {
		slog.Error("unmarshal wrapper failed", "error", err)
		os.Exit(1)
	}
	payloadBytes, err := json.Marshal(wrapper)
	if err != nil {
		slog.Error("marshal sorted payload failed", "error", err)
		os.Exit(1)
	}

	hash := sha256.Sum256(payloadBytes)

	// signature block (127 bytes, big-endian for RSA):
	// U = zero(127) with hash at [95:127]
	// block = U XOR PADKEY
	U := make([]byte, 127)
	copy(U[95:], hash[:])
	beBlock := make([]byte, 127)
	for i := 0; i < 127; i++ {
		beBlock[i] = U[i] ^ padKey[i]
	}
	if beBlock[0] == 0 {
		beBlock[0] ^= 1
	}

	m := new(big.Int).SetBytes(beBlock)
	s := new(big.Int).Exp(m, d, n)

	sigBytes := s.Bytes()
	if len(sigBytes) < 128 {
		pad := make([]byte, 128-len(sigBytes))
		sigBytes = append(pad, sigBytes...)
	}
	sigBytesLe := make([]byte, 128)
	for i := 0; i < 128; i++ {
		sigBytesLe[i] = sigBytes[127-i]
	}

	hexlic := Hexlic{
		Header:    map[string]int{"version": 1},
		Payload:   payload,
		Signature: fmt.Sprintf("%X", sigBytesLe),
	}

	finalBytes, _ := json.Marshal(hexlic)
	if err = os.WriteFile("ida.hexlic", finalBytes, 0644); err != nil {
		slog.Error("failed to write ida.hexlic", "error", err)
		os.Exit(1)
	}

	slog.Info("gen ida.hexlic done!")
}

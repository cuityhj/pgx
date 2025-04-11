package pgproto3

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/cuityhj/pgx/v5/internal/pgio"
)

const (
	AuthMechanismSCRAMSHA256 = "SCRAM-SHA-256"
	AuthMechanismECDHESHA256 = "ECDHE-RSA-AES128-GCM-SHA256"
)

// AuthenticationSASL is a message sent from the backend indicating that SASL authentication is required.
type AuthenticationSASL struct {
	AuthMechanisms []string
}

// Backend identifies this message as sendable by the PostgreSQL backend.
func (*AuthenticationSASL) Backend() {}

// Backend identifies this message as an authentication response.
func (*AuthenticationSASL) AuthenticationResponse() {}

// Decode decodes src into dst. src must contain the complete message with the exception of the initial 1 byte message
// type identifier and 4 byte message length.
func (dst *AuthenticationSASL) Decode(src []byte) error {
	if len(src) < 4 {
		return errors.New("authentication message too short")
	}

	authType := binary.BigEndian.Uint32(src)

	if authType != AuthTypeSASL {
		return errors.New("bad auth type")
	}

	authMechanisms := src[4:]
	for len(authMechanisms) > 1 {
		idx := bytes.IndexByte(authMechanisms, 0)
		if idx == -1 {
			if len(src) < 128 {
				return &invalidMessageFormatErr{messageType: "AuthenticationSASL", details: "unterminated string"}
			} else {
				dst.decodeECDHESHA256(src)
				break
			}
		}

		dst.AuthMechanisms = append(dst.AuthMechanisms, string(authMechanisms[:idx]))
		authMechanisms = authMechanisms[idx+1:]
	}

	return nil
}

func (dst *AuthenticationSASL) decodeECDHESHA256(src []byte) {
	var buf bytes.Buffer
	buf.Write(src[8:])
	dst.AuthMechanisms = []string{
		AuthMechanismECDHESHA256, //"ECDHE-RSA-AES128-GCM-SHA256"
		string(buf.Next(64)),     //random64code
		string(buf.Next(8)),      //token
		"10000",                  //serverIteration = strconv.Itoa(int(int32(binary.BigEndian.Uint32([]byte{0, 0, 39, 16}))))
	}
}

// Encode encodes src into dst. dst will include the 1 byte message type identifier and the 4 byte message length.
func (src *AuthenticationSASL) Encode(dst []byte) ([]byte, error) {
	dst, sp := beginMessage(dst, 'R')
	dst = pgio.AppendUint32(dst, AuthTypeSASL)

	for _, s := range src.AuthMechanisms {
		dst = append(dst, []byte(s)...)
		dst = append(dst, 0)
	}
	dst = append(dst, 0)

	return finishMessage(dst, sp)
}

// MarshalJSON implements encoding/json.Marshaler.
func (src AuthenticationSASL) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type           string
		AuthMechanisms []string
	}{
		Type:           "AuthenticationSASL",
		AuthMechanisms: src.AuthMechanisms,
	})
}

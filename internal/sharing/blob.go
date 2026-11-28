package sharing

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

const (
	CSKeyMagic       = "CSKEY"
	CSKeyVersion     = 1
	KeyAlgID         = 1
	WrapAlgID        = 1
	FingerprintLen   = 32
	HeaderSize       = 108
	MaxBlobSize      = 8192
	MinBlobSize      = 112
	MaxWrappedKeyLen = 4096
)

type BlobHeader struct {
	Version              uint8
	KeyAlg               uint8
	ShareRequestID       uuid.UUID
	FileID               uuid.UUID
	OwnerFingerprint     string
	RequesterFingerprint string
	WrapAlg              uint8
	WrappedKeyLen        uint16
}

type DecodedBlob struct {
	Header     BlobHeader
	WrappedDEK []byte
	Signature  []byte
	SignedData []byte 
}

func parseFingerprintBytes(fpStr string) ([]byte, error) {
	b, err := hex.DecodeString(fpStr)
	if err != nil || len(b) != FingerprintLen {
		return nil, fmt.Errorf("invalid fingerprint hex (%s)", fpStr)
	}
	return b, nil
}

// EncodeBlob create an owner-signed .cskey blob envelope.
func EncodeBlob(req ShareRequest, wrappedDEK []byte, signFunc func(digest []byte) ([]byte, error)) ([]byte, error) {
	if len(wrappedDEK) < 1 || len(wrappedDEK) > MaxWrappedKeyLen {
		return nil, fmt.Errorf("wrapped key length %d out of range [1, %d]", len(wrappedDEK), MaxWrappedKeyLen)
	}

	ownerFP, err := parseFingerprintBytes(req.Owner.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("owner fingerprint: %w", err)
	}

	requesterFP, err := parseFingerprintBytes(req.Requester.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("requester fingerprint: %w", err)
	}

	header := make([]byte, HeaderSize)
	copy(header[0:5], []byte(CSKeyMagic))
	header[5] = CSKeyVersion
	header[6] = KeyAlgID

	reqIDBytes := req.ID
	copy(header[7:23], reqIDBytes[:])

	fileIDBytes := req.FileID
	copy(header[23:39], fileIDBytes[:])

	header[39] = FingerprintLen
	copy(header[40:72], ownerFP)

	header[72] = FingerprintLen
	copy(header[73:105], requesterFP)

	header[105] = WrapAlgID
	binary.BigEndian.PutUint16(header[106:108], uint16(len(wrappedDEK)))

	signedData := make([]byte, HeaderSize+len(wrappedDEK))
	copy(signedData[:HeaderSize], header)
	copy(signedData[HeaderSize:], wrappedDEK)

	digest := sha256.Sum256(signedData)
	sig, err := signFunc(digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}

	trailer := make([]byte, 2)
	binary.BigEndian.PutUint16(trailer, uint16(len(sig)))

	totalLen := len(signedData) + len(trailer) + len(sig)
	if totalLen > MaxBlobSize {
		return nil, fmt.Errorf("blob total size %d exceeds max %d", totalLen, MaxBlobSize)
	}

	blob := make([]byte, 0, totalLen)
	blob = append(blob, signedData...)
	blob = append(blob, trailer...)
	blob = append(blob, sig...)

	return blob, nil
}

// DecodeBlob parse and validates the binary envelope of a .cskey blob.
func DecodeBlob(data []byte) (*DecodedBlob, error) {
	if len(data) < MinBlobSize || len(data) > MaxBlobSize {
		return nil, ErrValidationFailed
	}

	if string(data[0:5]) != CSKeyMagic {
		return nil, ErrValidationFailed
	}

	if data[5] != CSKeyVersion {
		return nil, ErrValidationFailed
	}

	if data[6] != KeyAlgID {
		return nil, ErrValidationFailed
	}

	shareRequestID, err := uuid.FromBytes(data[7:23])
	if err != nil {
		return nil, ErrValidationFailed
	}

	fileID, err := uuid.FromBytes(data[23:39])
	if err != nil {
		return nil, ErrValidationFailed
	}

	if data[39] != FingerprintLen {
		return nil, ErrValidationFailed
	}
	ownerFP := hex.EncodeToString(data[40:72])

	if data[72] != FingerprintLen {
		return nil, ErrValidationFailed
	}
	requesterFP := hex.EncodeToString(data[73:105])

	if data[105] != WrapAlgID {
		return nil, ErrValidationFailed
	}

	n := binary.BigEndian.Uint16(data[106:108])
	if n < 1 || n > MaxWrappedKeyLen {
		return nil, ErrValidationFailed
	}

	payloadEnd := HeaderSize + int(n)
	if payloadEnd+2 > len(data) {
		return nil, ErrValidationFailed
	}

	m := binary.BigEndian.Uint16(data[payloadEnd : payloadEnd+2])
	if payloadEnd+2+int(m) != len(data) {
		return nil, ErrValidationFailed
	}

	wrappedDEK := data[HeaderSize:payloadEnd]
	sig := data[payloadEnd+2 : len(data)]
	signedData := data[:payloadEnd]

	header := BlobHeader{
		Version:              data[5],
		KeyAlg:               data[6],
		ShareRequestID:       shareRequestID,
		FileID:               fileID,
		OwnerFingerprint:     ownerFP,
		RequesterFingerprint: requesterFP,
		WrapAlg:              data[105],
		WrappedKeyLen:        n,
	}

	return &DecodedBlob{
		Header:     header,
		WrappedDEK: wrappedDEK,
		Signature:  sig,
		SignedData: signedData,
	}, nil
}

// VerifyBlob check envelope consistency with the share request and verifiy the owner signature.
func VerifyBlob(decoded *DecodedBlob, req ShareRequest, verifyFunc func(ownerID uuid.UUID, digest, sig []byte) (bool, error)) error {
	if decoded.Header.ShareRequestID != req.ID {
		return ErrValidationFailed
	}

	if decoded.Header.FileID != req.FileID {
		return ErrValidationFailed
	}

	if decoded.Header.OwnerFingerprint != req.Owner.Fingerprint {
		return ErrValidationFailed
	}

	if decoded.Header.RequesterFingerprint != req.Requester.Fingerprint {
		return ErrValidationFailed
	}

	digest := sha256.Sum256(decoded.SignedData)
	valid, err := verifyFunc(req.Owner.ID, digest[:], decoded.Signature)
	if err != nil || !valid {
		return ErrValidationFailed
	}

	return nil
}

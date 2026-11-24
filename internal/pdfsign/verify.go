package pdfsign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
)

type SignatureVerificationResult struct {
	Valid       bool
	SignerID    string
	SignedAt    time.Time
	Reason      string // "", "content_modified", "unknown_signer", "no_signature"
	Certificate *x509.Certificate
}

// VerifyPDF inspects all signatures present in the PDF and verifies their byte ranges and cryptographic validity.
func VerifyPDF(ctx context.Context, pdfBytes []byte, keysSvc keys.Service, expectedUserID uuid.UUID) ([]SignatureVerificationResult, error) {
	allRanges, err := ComputeAllByteRanges(pdfBytes)
	if err != nil || len(allRanges) == 0 {
		return []SignatureVerificationResult{{
			Valid:  false,
			Reason: "no_signature",
		}}, nil
	}

	contentsSlots, err := extractAllContentsHex(pdfBytes)
	if err != nil || len(contentsSlots) == 0 {
		return []SignatureVerificationResult{{
			Valid:  false,
			Reason: "no_signature",
		}}, nil
	}

	n := len(allRanges)
	if len(contentsSlots) < n {
		n = len(contentsSlots)
	}

	var results []SignatureVerificationResult

	for i := 0; i < n; i++ {
		br := allRanges[i]
		hexSlot := contentsSlots[i]

		if isZeroFilledHex(hexSlot) {
			results = append(results, SignatureVerificationResult{
				Valid:  false,
				Reason: "no_signature",
			})
			continue
		}

		cmsBytes, err := hex.DecodeString(hexSlot)
		if err != nil {
			results = append(results, SignatureVerificationResult{
				Valid:  false,
				Reason: "content_modified",
			})
			continue
		}

		cmsInfo, err := ParseCMSSignedData(cmsBytes)
		if err != nil {
			results = append(results, SignatureVerificationResult{
				Valid:  false,
				Reason: "content_modified",
			})
			continue
		}

		off1, len1, off2, len2 := br[0], br[1], br[2], br[3]
		if off1 < 0 || len1 < 0 || off2 < 0 || len2 < 0 || off2+len2 > int64(len(pdfBytes)) {
			results = append(results, SignatureVerificationResult{
				Valid:  false,
				Reason: "content_modified",
			})
			continue
		}

		hash := sha256.New()
		hash.Write(pdfBytes[off1 : off1+len1])
		hash.Write(pdfBytes[off2 : off2+len2])
		recomputedDigest := hash.Sum(nil)

		if !bytesEqual(cmsInfo.MessageDigest, recomputedDigest) {
			results = append(results, SignatureVerificationResult{
				Valid:  false,
				Reason: "content_modified",
			})
			continue
		}

		var pubKey *rsa.PublicKey
		var cert *x509.Certificate
		if keysSvc != nil && expectedUserID != uuid.Nil {
			if kp, kpErr := keysSvc.Get(ctx, expectedUserID); kpErr == nil && kp.PublicKey != nil {
				pubKey = kp.PublicKey
				cert = kp.Certificate
			} else {
				results = append(results, SignatureVerificationResult{
					Valid:  false,
					Reason: "unknown_signer",
				})
				continue
			}
		} else if len(cmsInfo.Certificates) > 0 {
			parsedCert, parseErr := x509.ParseCertificate(cmsInfo.Certificates[0])
			if parseErr == nil {
				cert = parsedCert
				if pk, ok := parsedCert.PublicKey.(*rsa.PublicKey); ok {
					pubKey = pk
				}
			}
		}

		if pubKey == nil {
			results = append(results, SignatureVerificationResult{
				Valid:  false,
				Reason: "unknown_signer",
			})
			continue
		}

		valid := false
		if len(cmsInfo.RawSignedAttrsSet) > 0 {
			attrDigest := sha256Sum(cmsInfo.RawSignedAttrsSet)
			if vErr := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, attrDigest, cmsInfo.Signature); vErr == nil {
				valid = true
			}
		} else {
			// RawSignedAttrsSet is empty
		}

		signerID := "unknown"
		if cert != nil {
			signerID = cert.Subject.CommonName
			if signerID == "" {
				signerID = cert.Subject.String()
			}
		}

		reason := ""
		if !valid {
			reason = "unknown_signer"
		}

		results = append(results, SignatureVerificationResult{
			Valid:       valid,
			SignerID:    signerID,
			SignedAt:    cmsInfo.SigningTime,
			Reason:      reason,
			Certificate: cert,
		})
	}

	return results, nil
}

func extractAllContentsHex(pdfBytes []byte) ([]string, error) {
	contentsMarker := []byte("/Contents <")
	var slots []string

	searchOffset := 0
	for {
		idx := bytes.Index(pdfBytes[searchOffset:], contentsMarker)
		if idx == -1 {
			break
		}
		actualIdx := searchOffset + idx
		startHex := actualIdx + len(contentsMarker)
		closeAngle := bytes.Index(pdfBytes[startHex:], []byte(">"))
		if closeAngle == -1 {
			searchOffset = startHex
			continue
		}
		endHex := startHex + closeAngle
		hexStr := string(pdfBytes[startHex:endHex])
		slots = append(slots, hexStr)
		searchOffset = endHex + 1
	}

	return slots, nil
}

func isZeroFilledHex(s string) bool {
	for _, ch := range s {
		if ch != '0' {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

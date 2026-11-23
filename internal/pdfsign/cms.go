package pdfsign

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"time"

	pdfasn1 "github.com/ilhmpbta/CypherSecurity/internal/pdfsign/asn1"
)

var (
	ErrInvalidCMS = errors.New("pdfsign: invalid CMS SignedData blob")
)

// BuildCMSSignedData constructs a DER-encoded CMS SignedData ContentInfo (`adbe.pkcs7.detached`).
func BuildCMSSignedData(digest []byte, certDER []byte, signFunc func(digestToSign []byte) ([]byte, error)) ([]byte, error) {
	sha256AlgID := pdfasn1.EncodeSequence(
		pdfasn1.EncodeOID(pdfasn1.OIDSha256),
		pdfasn1.EncodeNull(),
	)

	encapContentInfo := pdfasn1.EncodeSequence(
		pdfasn1.EncodeOID(pdfasn1.OIDData),
	)

	var certsSet []byte
	if len(certDER) > 0 {
		certsSet = pdfasn1.EncodeContextSpecific(0, true, certDER)
	}

	now := time.Now().UTC()

	attrContentType := pdfasn1.EncodeSequence(
		pdfasn1.EncodeOID(pdfasn1.OIDContentType),
		pdfasn1.EncodeSet(pdfasn1.EncodeOID(pdfasn1.OIDData)),
	)

	attrMessageDigest := pdfasn1.EncodeSequence(
		pdfasn1.EncodeOID(pdfasn1.OIDMessageDigest),
		pdfasn1.EncodeSet(pdfasn1.EncodeOctetString(digest)),
	)

	attrSigningTime := pdfasn1.EncodeSequence(
		pdfasn1.EncodeOID(pdfasn1.OIDSigningTime),
		pdfasn1.EncodeSet(pdfasn1.EncodeUTCTime(now)),
	)

	signedAttrsSetBytes := pdfasn1.EncodeSet(sortDEREncodings([][]byte{attrContentType, attrMessageDigest, attrSigningTime})...)
	attrDigest := sha256Sum(signedAttrsSetBytes)

	sigBytes, err := signFunc(attrDigest)
	if err != nil {
		return nil, fmt.Errorf("cms sign failed: %w", err)
	}

	var issuerAndSerial []byte
	if len(certDER) > 0 {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("parse x509 certificate: %w", err)
		}
		issuerAndSerial = pdfasn1.EncodeSequence(
			cert.RawIssuer,
			pdfasn1.EncodeBigInt(cert.SerialNumber),
		)
	} else {
		issuerAndSerial = pdfasn1.EncodeSequence(
			pdfasn1.EncodeSequence(),
			pdfasn1.EncodeInteger(1),
		)
	}

	version1 := pdfasn1.EncodeInteger(1)
	signatureAlgorithm := pdfasn1.EncodeSequence(
		pdfasn1.EncodeOID(pdfasn1.OIDSha256WithRSA),
		pdfasn1.EncodeNull(),
	)

	signedAttrsTagged := pdfasn1.EncodeContextSpecific(0, true, signedAttrsSetBytes)

	signerInfo := pdfasn1.EncodeSequence(
		version1,
		issuerAndSerial,
		sha256AlgID,
		signedAttrsTagged,
		signatureAlgorithm,
		pdfasn1.EncodeOctetString(sigBytes),
	)

	digestAlgorithmsSet := pdfasn1.EncodeSet(sha256AlgID)
	signerInfosSet := pdfasn1.EncodeSet(signerInfo)

	signedDataSeq := pdfasn1.EncodeSequence(
		version1,
		digestAlgorithmsSet,
		encapContentInfo,
		certsSet,
		signerInfosSet,
	)

	signedDataExplicit := pdfasn1.EncodeContextSpecific(0, true, signedDataSeq)

	contentInfo := pdfasn1.EncodeSequence(
		pdfasn1.EncodeOID(pdfasn1.OIDSignedData),
		signedDataExplicit,
	)

	return contentInfo, nil
}

// CMSInfo holds parsed information from a CMS SignedData blob.
type CMSInfo struct {
	MessageDigest     []byte
	Signature         []byte
	SigningTime       time.Time
	Certificates      [][]byte
	RawSignedAttrsSet []byte
}

// ParseCMSSignedData parses a DER CMS SignedData blob to extract message digest, signature, certificates, and signing time.
func ParseCMSSignedData(cmsBytes []byte) (CMSInfo, error) {
	var info CMSInfo

	// 1. Decode ContentInfo SEQUENCE
	ciElem, _, err := pdfasn1.DecodeDER(cmsBytes)
	if err != nil || ciElem.Tag != pdfasn1.TagSequence {
		return info, fmt.Errorf("%w: invalid ContentInfo sequence", ErrInvalidCMS)
	}

	inner := ciElem.Content
	_, inner, err = pdfasn1.DecodeDER(inner) // OID
	if err != nil {
		return info, fmt.Errorf("%w: missing ContentInfo OID", ErrInvalidCMS)
	}

	sdElem, _, err := pdfasn1.DecodeDER(inner)
	if err != nil {
		return info, fmt.Errorf("%w: missing SignedData content", ErrInvalidCMS)
	}

	sdBytes := sdElem.Content
	if sdElem.Tag == 0xa0 {
		subElem, _, err := pdfasn1.DecodeDER(sdElem.Content)
		if err == nil {
			sdBytes = subElem.Full
		}
	}

	seqElem, _, err := pdfasn1.DecodeDER(sdBytes)
	if err != nil || seqElem.Tag != pdfasn1.TagSequence {
		seqElem, _, err = pdfasn1.DecodeDER(sdElem.Full)
		if err != nil || seqElem.Tag != pdfasn1.TagSequence {
			return info, fmt.Errorf("%w: invalid SignedData sequence", ErrInvalidCMS)
		}
	}

	sdContent := seqElem.Content
	// Version
	_, sdContent, err = pdfasn1.DecodeDER(sdContent)
	if err != nil {
		return info, err
	}
	// DigestAlgorithms
	_, sdContent, err = pdfasn1.DecodeDER(sdContent)
	if err != nil {
		return info, err
	}
	// EncapContentInfo
	_, sdContent, err = pdfasn1.DecodeDER(sdContent)
	if err != nil {
		return info, err
	}

	// Optional Certificates ([0], 0xa0)
	if len(sdContent) > 0 {
		elem, restContent, err := pdfasn1.DecodeDER(sdContent)
		if err == nil {
			if elem.Tag == 0xa0 {
				sdContent = restContent
				certRest := elem.Content
				var certs [][]byte
				for len(certRest) > 0 {
					cElem, nextC, err := pdfasn1.DecodeDER(certRest)
					if err != nil {
						break
					}
					if cElem.Tag == pdfasn1.TagSequence {
						certs = append(certs, cElem.Full)
					}
					certRest = nextC
				}
				info.Certificates = certs
			}
		}
	}

	// Optional CRLs ([1], 0xa1)
	if len(sdContent) > 0 {
		elem, restContent, err := pdfasn1.DecodeDER(sdContent)
		if err == nil {
			if elem.Tag == 0xa1 {
				sdContent = restContent
			}
		}
	}

	// SignerInfos (SET)
	if len(sdContent) == 0 {
		return info, fmt.Errorf("%w: missing SignerInfos", ErrInvalidCMS)
	}
	siSetElem, _, err := pdfasn1.DecodeDER(sdContent)
	if err != nil || siSetElem.Tag != pdfasn1.TagSet {
		return info, fmt.Errorf("%w: invalid SignerInfos set", ErrInvalidCMS)
	}

	siRest := siSetElem.Content
	if len(siRest) == 0 {
		return info, fmt.Errorf("%w: empty SignerInfos set", ErrInvalidCMS)
	}
	siElem, _, err := pdfasn1.DecodeDER(siRest)
	if err != nil || siElem.Tag != pdfasn1.TagSequence {
		return info, fmt.Errorf("%w: invalid SignerInfo sequence", ErrInvalidCMS)
	}

	siContent := siElem.Content
	// Version
	_, siContent, err = pdfasn1.DecodeDER(siContent)
	if err != nil {
		return info, err
	}
	// Sid
	_, siContent, err = pdfasn1.DecodeDER(siContent)
	if err != nil {
		return info, err
	}
	// DigestAlgorithm
	_, siContent, err = pdfasn1.DecodeDER(siContent)
	if err != nil {
		return info, err
	}

	// Optional SignedAttrs ([0], 0xa0)
	if len(siContent) > 0 {
		elem, restContent, err := pdfasn1.DecodeDER(siContent)
		if err == nil {
			if elem.Tag == 0xa0 {
				siContent = restContent
				info.RawSignedAttrsSet = elem.Content

				attrRest := elem.Content
				for len(attrRest) > 0 {
					attrElem, nextAttr, err := pdfasn1.DecodeDER(attrRest)
					if err != nil {
						break
					}
					if attrElem.Tag == pdfasn1.TagSequence {
						aOid, aValRest, err := pdfasn1.DecodeDER(attrElem.Content)
						if err == nil && aOid.Tag == pdfasn1.TagOID {
							if bytes.Contains(aOid.Full, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04}) {
								vSet, _, err := pdfasn1.DecodeDER(aValRest)
								if err == nil {
									vOctet, _, err := pdfasn1.DecodeDER(vSet.Content)
									if err == nil && vOctet.Tag == pdfasn1.TagOctetString {
										info.MessageDigest = vOctet.Content
									}
								}
							} else if bytes.Contains(aOid.Full, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05}) {
								vSet, _, err := pdfasn1.DecodeDER(aValRest)
								if err == nil {
									tElem, _, err := pdfasn1.DecodeDER(vSet.Content)
									if err == nil {
										if tElem.Tag == pdfasn1.TagUTCTime || tElem.Tag == pdfasn1.TagGeneralizedTime {
											tStr := string(tElem.Content)
											layout := "060102150405Z"
											if len(tStr) > 13 {
												layout = "20060102150405Z"
											}
											if parsedT, pErr := time.Parse(layout, tStr); pErr == nil {
												info.SigningTime = parsedT.UTC()
											}
										}
									}
								}
							}
						}
					}
					attrRest = nextAttr
				}
			}
		}
	}

	// SignatureAlgorithm
	_, siContent, err = pdfasn1.DecodeDER(siContent)
	if err != nil {
		return info, err
	}

	// Signature (OCTET STRING)
	sigElem, _, err := pdfasn1.DecodeDER(siContent)
	if err == nil && sigElem.Tag == pdfasn1.TagOctetString {
		info.Signature = sigElem.Content
	}

	if len(info.MessageDigest) == 0 || len(info.Signature) == 0 {
		msgDig, sig, err := parseCMSFieldsFallback(cmsBytes)
		if err == nil {
			if len(info.MessageDigest) == 0 {
				info.MessageDigest = msgDig
			}
			if len(info.Signature) == 0 {
				info.Signature = sig
			}
		}
	}

	return info, nil
}

func parseCMSFieldsFallback(cmsBytes []byte) ([]byte, []byte, error) {
	oidDigest := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04}
	idx := bytes.Index(cmsBytes, oidDigest)
	var messageDigest []byte
	if idx != -1 {
		sub := cmsBytes[idx+len(oidDigest):]
		for i := 0; i < len(sub)-2; i++ {
			if sub[i] == 0x04 {
				elem, _, derr := pdfasn1.DecodeDER(sub[i:])
				if derr == nil && len(elem.Content) == 32 {
					messageDigest = elem.Content
					break
				}
			}
		}
	}

	var signature []byte
	searchOffset := 0
	for {
		idx04 := bytes.Index(cmsBytes[searchOffset:], []byte{0x04})
		if idx04 == -1 {
			break
		}
		actualIdx := searchOffset + idx04
		elem, _, derr := pdfasn1.DecodeDER(cmsBytes[actualIdx:])
		if derr == nil {
			if len(elem.Content) >= 128 && len(elem.Content) <= 512 {
				signature = elem.Content
			}
		}
		searchOffset = actualIdx + 1
	}

	if messageDigest == nil || signature == nil {
		return nil, nil, errors.New("could not extract messageDigest or signature from CMS")
	}

	return messageDigest, signature, nil
}

func sortDEREncodings(elements [][]byte) [][]byte {
	sorted := make([][]byte, len(elements))
	copy(sorted, elements)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i], sorted[j]) < 0
	})
	return sorted
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

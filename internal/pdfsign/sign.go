package pdfsign

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/ilhmpbta/CypherSecurity/internal/keys"
)

// SignPDF appends an incremental signature update to the PDF and signs the byte ranges using keys.Service.
func SignPDF(ctx context.Context, orig []byte, keysSvc keys.Service, sess keys.Session) ([]byte, error) {
	if keysSvc == nil {
		return nil, fmt.Errorf("%w: keys service is required", ErrSignatureFailed)
	}

	// Ensure user keypair exists and retrieve certificate DER if available
	kp, err := keysSvc.EnsureForUser(ctx, sess)
	if err != nil {
		return nil, fmt.Errorf("%w: ensure user keypair failed: %v", ErrSignatureFailed, err)
	}

	// 1. Perform incremental update to add signature dictionary, widget, acroform, catalog update, and xref
	updatedPDF, err := IncrementalUpdate(orig)
	if err != nil {
		return nil, fmt.Errorf("%w: incremental update failed: %v", ErrSignatureFailed, err)
	}

	// 2. Compute ByteRange
	br, err := ComputeByteRange(updatedPDF)
	if err != nil {
		return nil, fmt.Errorf("%w: compute byte range failed: %v", ErrSignatureFailed, err)
	}

	off1, len1, off2, len2 := br[0], br[1], br[2], br[3]
	if off1 < 0 || len1 < 0 || off2 < 0 || len2 < 0 || off2+len2 > int64(len(updatedPDF)) {
		return nil, fmt.Errorf("%w: invalid byte range bounds", ErrSignatureFailed)
	}

	// 3. Extract the two byte ranges and compute SHA-256 digest
	hash := sha256.New()
	hash.Write(updatedPDF[off1 : off1+len1])
	hash.Write(updatedPDF[off2 : off2+len2])
	digest := hash.Sum(nil)

	// 4. Build CMS SignedData detached signature
	cmsBytes, err := BuildCMSSignedData(digest, kp.CertificateDER, func(digestToSign []byte) ([]byte, error) {
		return keysSvc.Sign(ctx, sess, digestToSign)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: build CMS signed data failed: %v", ErrSignatureFailed, err)
	}

	// 5. Inject encoded CMS signature bytes into the /Contents slot
	signedPDF, err := InjectSignature(updatedPDF, cmsBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: inject signature failed: %v", ErrSignatureFailed, err)
	}

	return signedPDF, nil
}

package asn1

// Standard cryptographic and CMS OIDs represented as integer slices.
var (
	OIDData          = []int{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData    = []int{1, 2, 840, 113549, 1, 7, 2}
	OIDSha256        = []int{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDRsaEncryption = []int{1, 2, 840, 113549, 1, 1, 1}
	OIDSha256WithRSA = []int{1, 2, 840, 113549, 1, 1, 11}
	OIDContentType   = []int{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest = []int{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime   = []int{1, 2, 840, 113549, 1, 9, 5}
)

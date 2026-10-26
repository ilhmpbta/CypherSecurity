// Package academic implements AES-128 and AES-256 in CBC mode with PKCS#7
// padding and in CTR mode, RC4, and DES in CBC mode with PKCS#7 padding.
//
// RC4 and DES are cryptographically broken and are provided for academic
// comparison and benchmarking only. AES-CBC and AES-CTR provide confidentiality
// but not integrity, so they do not authenticate ciphertext.
//
// Production encryption lives in internal/crypto/production and uses
// AES-256-GCM. This package is imported only by ./benchmark; any other import
// fails the academic-isolation CI job.
//
// Every encrypt function returns (iv, ciphertext, error), and every decrypt
// function takes (key, iv, ciphertext) and returns (plaintext, error). IV is
// returned separately from the ciphertext; this package never concatenates
// them. RC4 is the exception to having an IV value: it returns nil because RC4
// is a stream cipher, and its decrypt function requires a nil IV.
package academic

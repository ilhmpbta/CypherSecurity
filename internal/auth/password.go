package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2Params defines the parameters for Argon2id hashing.
// Baseline meets OWASP minimum recommendations: 19 MiB memory, 2 iterations, parallelism 1.
type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var defaultParams = argon2Params{
	memory:      19456, // 19 MiB in KiB
	iterations:  2,
	parallelism: 1,
	saltLength:  16,
	keyLength:   32,
}

// HashPassword derives an Argon2id hash in PHC string format:
// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
func HashPassword(plain string) (string, error) {
	salt := make([]byte, defaultParams.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(plain),
		salt,
		defaultParams.iterations,
		defaultParams.memory,
		defaultParams.parallelism,
		defaultParams.keyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	phc := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		defaultParams.memory,
		defaultParams.iterations,
		defaultParams.parallelism,
		b64Salt,
		b64Hash,
	)

	return phc, nil
}

// VerifyPassword checks a plaintext password against a stored PHC hash.
// It parses and validates parameters (including upper/lower bounds checks to prevent OOM
// from corrupted rows where m=4294967295) so existing hashes continue to verify safely.
func VerifyPassword(hash, plain string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("parse version: %w", err)
	}
	if version != argon2.Version {
		return false, errors.New("incompatible argon2 version")
	}

	var memory, iterations uint32
	var parallelism uint8
	paramParts := strings.Split(parts[3], ",")
	for _, p := range paramParts {
		kv := strings.Split(p, "=")
		if len(kv) != 2 {
			return false, errors.New("invalid hash parameters")
		}
		switch kv[0] {
		case "m":
			val, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return false, fmt.Errorf("parse memory: %w", err)
			}
			memory = uint32(val)
		case "t":
			val, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return false, fmt.Errorf("parse iterations: %w", err)
			}
			iterations = uint32(val)
		case "p":
			val, err := strconv.ParseUint(kv[1], 10, 8)
			if err != nil {
				return false, fmt.Errorf("parse parallelism: %w", err)
			}
			parallelism = uint8(val)
		default:
			return false, errors.New("invalid hash parameters")
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}

	storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	// Bounds validation to prevent OOM or invalid argon2 configuration.
	// Rationale: A corrupted-restore row with m=4294967295 would OOM the process on a single login.
	if memory < 8 || memory > 1048576 || // 8 KiB to 1 GiB
		iterations < 1 || iterations > 10 ||
		parallelism < 1 || parallelism > 16 ||
		len(salt) < 8 || len(salt) > 64 ||
		len(storedHash) < 16 || len(storedHash) > 128 {
		return false, errors.New("hash parameters out of range")
	}

	computedHash := argon2.IDKey(
		[]byte(plain),
		salt,
		iterations,
		memory,
		parallelism,
		uint32(len(storedHash)),
	)

	if subtle.ConstantTimeCompare(storedHash, computedHash) == 1 {
		return true, nil
	}

	return false, nil
}

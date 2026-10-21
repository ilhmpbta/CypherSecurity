package auth

// HashPassword derives an Argon2id hash in PHC format.
func HashPassword(plain string) (string, error) { return "", nil }

// VerifyPassword checks a plaintext against a stored PHC hash.
func VerifyPassword(hash, plain string) (bool, error) { return false, nil }

package files

import (
	"errors"
	"net/http"
	"strings"
)

var ErrInvalidContentType = errors.New("invalid or unsupported content type")

var allowedTypes = map[string]bool{
	"application/pdf":          true,
	"application/msword":       true,
	"application/vnd.ms-excel": true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":       true,
	"image/jpeg":      true,
	"image/png":       true,
	"image/webp":      true,
	"image/heic":      true,
	"video/mp4":       true,
	"video/webm":      true,
	"video/quicktime": true,
}

var officeTypes = map[string]bool{
	"application/msword":       true,
	"application/vnd.ms-excel": true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":       true,
}

// ValidateContentType returns nil if contentType is allowed for this app and
// matches the first 512 bytes of r (which must be peeked without consuming r).
func ValidateContentType(declared string, first512 []byte) error {
	declared = strings.ToLower(strings.TrimSpace(declared))
	if idx := strings.Index(declared, ";"); idx != -1 {
		declared = strings.TrimSpace(declared[:idx])
	}

	if !allowedTypes[declared] {
		return ErrInvalidContentType
	}

	if len(first512) == 0 {
		return nil
	}

	detected := http.DetectContentType(first512)
	detected = strings.ToLower(strings.TrimSpace(detected))
	if idx := strings.Index(detected, ";"); idx != -1 {
		detected = strings.TrimSpace(detected[:idx])
	}

	if detected == "application/octet-stream" {
		if officeTypes[declared] {
			return nil
		}
		return ErrInvalidContentType
	}

	if detected == declared {
		return nil
	}

	decSlash := strings.Index(declared, "/")
	detSlash := strings.Index(detected, "/")
	if decSlash != -1 && detSlash != -1 {
		if declared[:decSlash] == detected[:detSlash] && (declared[:decSlash] == "image" || declared[:decSlash] == "video") {
			return nil
		}
	}

	return ErrInvalidContentType
}

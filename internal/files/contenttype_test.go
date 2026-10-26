package files

import (
	"testing"
)

func TestValidateContentType(t *testing.T) {
	pdfBytes := []byte("%PDF-1.4 some pdf content...")
	jpegBytes := []byte("\xff\xd8\xff\xe0 some jpeg content...")
	htmlBytes := []byte("<html><body>hello</body></html>")
	officeBytes := []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 some ole2 doc")

	tests := []struct {
		name     string
		declared string
		first512 []byte
		wantErr  bool
	}{
		{"Valid PDF", "application/pdf", pdfBytes, false},
		{"Valid JPEG", "image/jpeg", jpegBytes, false},
		{"Valid JPEG with charset", "image/jpeg; charset=utf-8", jpegBytes, false},
		{"Mismatched PDF/HTML", "application/pdf", htmlBytes, true},
		{"Disallowed type", "application/x-sh", pdfBytes, true},
		{"Office doc octet-stream allowed", "application/msword", officeBytes, false},
		{"Office doc octet-stream wrong declared", "image/jpeg", officeBytes, true},
		{"Empty file allowed", "application/pdf", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContentType(tt.declared, tt.first512)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContentType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

package files

import (
	"testing"
)

func TestValidateContentType(t *testing.T) {
	pdfBytes := []byte("%PDF-1.4 some pdf content...")
	jpegBytes := []byte("\xff\xd8\xff\xe0 some jpeg content...")
	htmlBytes := []byte("<html><body>hello</body></html>")
	officeBytes := []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 some ole2 doc")
	zipBytes := []byte("PK\x03\x04 some zip / docx / xlsx content")
	octetBytes := []byte{0x00, 0x01, 0x02, 0x03}

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
		{"Valid DOCX with zip prefix", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", zipBytes, false},
		{"Valid XLSX with zip prefix", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", zipBytes, false},
		{"DOCX with PDF prefix", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", pdfBytes, true},
		{"HEIC with octet-stream prefix", "image/heic", octetBytes, false},
		{"MOV with octet-stream prefix", "video/quicktime", octetBytes, false},
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

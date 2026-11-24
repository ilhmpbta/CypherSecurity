package pdfsign

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	SubFilterPkcs7Detached = "/adbe.pkcs7.detached"
	ContentsHexSize        = 32768 // 16 KiB raw = 32768 hex characters
)

var (
	ErrInvalidPDF      = errors.New("pdfsign: invalid or malformed PDF")
	ErrNoRoot          = errors.New("pdfsign: PDF catalog (/Root) not found")
	ErrSignatureFailed = errors.New("pdfsign: signature operation failed")
)

// Precompiled regexes for PDF structure parsing
var (
	reRoot   = regexp.MustCompile(`/Root\s+(\d+)\s+(\d+)\s+R`)
	rePrev   = regexp.MustCompile(`/Prev\s+(\d+)`)
	rePages  = regexp.MustCompile(`/Pages\s+(\d+)\s+(\d+)\s+R`)
	reObj    = regexp.MustCompile(`(?m)(?:^|[\r\n])\s*(\d+)\s+\d+\s+obj`)
	reFields = regexp.MustCompile(`/Fields\s*\[([^\]]*)\]`)
)

// IncrementalUpdateResult holds the result of appending an incremental signature update.
type IncrementalUpdateResult struct {
	UpdatedPDF     []byte
	ContentsOffset int64
	ContentsLength int64
}

// FindStartXref locates the byte offset of the last startxref keyword in the PDF.
func FindStartXref(data []byte) (int64, error) {
	idx := bytes.LastIndex(data, []byte("startxref"))
	if idx == -1 {
		return 0, fmt.Errorf("%w: startxref not found", ErrInvalidPDF)
	}

	rest := bytes.TrimSpace(data[idx+9:])
	endIdx := bytes.IndexAny(rest, " \t\r\n")
	if endIdx != -1 {
		rest = rest[:endIdx]
	}

	offset, err := strconv.ParseInt(string(rest), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid startxref offset: %v", ErrInvalidPDF, err)
	}

	if offset < 0 || offset >= int64(len(data)) {
		return 0, fmt.Errorf("%w: startxref offset out of range: %d", ErrInvalidPDF, offset)
	}

	return offset, nil
}

// ParseTrailer extracts the /Root object reference and optional /Prev offset from the trailer.
func ParseTrailer(data []byte, startXref int64) (rootObjNum int, rootGenNum int, prevOffset int64, err error) {
	if startXref < 0 || startXref >= int64(len(data)) {
		return 0, 0, 0, fmt.Errorf("%w: xref offset out of bounds", ErrInvalidPDF)
	}

	searchStart := startXref
	if searchStart > 1024 {
		searchStart = startXref - 1024
	}
	if searchStart < 0 {
		searchStart = 0
	}

	trailerBytes := data[searchStart:]
	tIdx := bytes.Index(trailerBytes, []byte("trailer"))
	if tIdx != -1 {
		dictBytes := trailerBytes[tIdx+7:]
		rootMatch := reRoot.FindSubmatch(dictBytes)
		if len(rootMatch) == 3 {
			rootObjNum, _ = strconv.Atoi(string(rootMatch[1]))
			rootGenNum, _ = strconv.Atoi(string(rootMatch[2]))
		}

		prevMatch := rePrev.FindSubmatch(dictBytes)
		if len(prevMatch) == 2 {
			prevOffset, _ = strconv.ParseInt(string(prevMatch[1]), 10, 64)
		}
	}

	if rootObjNum == 0 {
		rootMatch := reRoot.FindSubmatch(data)
		if len(rootMatch) == 3 {
			rootObjNum, _ = strconv.Atoi(string(rootMatch[1]))
			rootGenNum, _ = strconv.Atoi(string(rootMatch[2]))
		}
	}

	if rootObjNum == 0 {
		return 0, 0, 0, ErrNoRoot
	}

	return rootObjNum, rootGenNum, prevOffset, nil
}

// FindMaxObjNum scans the PDF for all object definitions (N M obj) to find the highest object number.
func FindMaxObjNum(data []byte) (int, error) {
	matches := reObj.FindAllSubmatch(data, -1)
	maxNum := 0
	for _, m := range matches {
		if len(m) == 2 {
			if n, err := strconv.Atoi(string(m[1])); err == nil {
				if n > maxNum {
					maxNum = n
				}
			}
		}
	}
	if maxNum == 0 {
		return 0, fmt.Errorf("%w: no objects found", ErrInvalidPDF)
	}
	return maxNum, nil
}

// ExtractPagesRef parses the /Pages reference from the Catalog object or defaults to "2 0 R".
func ExtractPagesRef(data []byte, rootObjNum int) string {
	// Search for catalog object in data using robust object header matching
	objHeaderPattern := regexp.MustCompile(fmt.Sprintf(`(?m)(?:^|[\r\n])\s*%d\s+\d+\s+obj`, rootObjNum))
	loc := objHeaderPattern.FindIndex(data)
	if loc == nil {
		return "2 0 R"
	}

	searchScope := data[loc[0]:]
	if len(searchScope) > 4096 {
		searchScope = searchScope[:4096]
	}

	match := rePages.FindSubmatch(searchScope)
	if len(match) == 3 {
		return fmt.Sprintf("%s %s R", match[1], match[2])
	}
	return "2 0 R"
}

// ExtractExistingFields gathers existing /Fields array contents from the PDF and determines signature count.
func ExtractExistingFields(data []byte) (existingFieldsStr string, sigCount int) {
	sigCount = bytes.Count(data, []byte("/FT /Sig"))

	// Find all /Fields [...] declarations
	matches := reFields.FindAll(data, -1)
	if len(matches) > 0 {
		// Use the latest /Fields declaration
		latest := string(matches[len(matches)-1])
		// Extract inner content between [ and ]
		openIdx := strings.Index(latest, "[")
		closeIdx := strings.LastIndex(latest, "]")
		if openIdx != -1 && closeIdx != -1 && closeIdx > openIdx {
			inner := strings.TrimSpace(latest[openIdx+1 : closeIdx])
			if inner != "" {
				return inner, sigCount
			}
		}
	}
	return "", sigCount
}

// IncrementalUpdate appends a new signature revision to the PDF.
func IncrementalUpdate(orig []byte) ([]byte, error) {
	if !bytes.HasPrefix(orig, []byte("%PDF-")) {
		return nil, fmt.Errorf("%w: missing %%PDF- header", ErrInvalidPDF)
	}

	prevStartXref, err := FindStartXref(orig)
	if err != nil {
		return nil, err
	}

	rootObjNum, rootGenNum, _, err := ParseTrailer(orig, prevStartXref)
	if err != nil {
		return nil, err
	}

	maxObj, err := FindMaxObjNum(orig)
	if err != nil {
		return nil, err
	}

	sigFieldObjID := maxObj + 1
	sigDictObjID := maxObj + 2
	acroFormObjID := maxObj + 3

	pagesRef := ExtractPagesRef(orig, rootObjNum)
	existingFields, sigCount := ExtractExistingFields(orig)
	sigName := fmt.Sprintf("Signature%d", sigCount+1)

	var buf bytes.Buffer
	buf.Write(orig)

	if !bytes.HasSuffix(orig, []byte("\n")) && !bytes.HasSuffix(orig, []byte("\r\n")) {
		buf.WriteByte('\n')
	}

	// 1. Signature Field Object (/Annot /Widget /FT /Sig)
	sigFieldOffset := int64(buf.Len())
	sigFieldObjStr := fmt.Sprintf(
		"%d 0 obj\n<<\n  /Type /Annot\n  /Subtype /Widget\n  /FT /Sig\n  /T (%s)\n  /V %d 0 R\n  /Rect [0 0 0 0]\n  /F 4\n>>\nendobj\n",
		sigFieldObjID, sigName, sigDictObjID,
	)
	buf.WriteString(sigFieldObjStr)

	// 2. Signature Dictionary Object (/Type /Sig)
	sigDictOffset := int64(buf.Len())
	placeholderByteRange := "[ 0000000000 0000000000 0000000000 0000000000 ]"
	contentsPlaceholder := strings.Repeat("0", ContentsHexSize)

	sigDictObjStr := fmt.Sprintf(
		"%d 0 obj\n<<\n  /Type /Sig\n  /Filter /Adobe.PPKLite\n  /SubFilter %s\n  /ByteRange %s\n  /Contents <%s>\n>>\nendobj\n",
		sigDictObjID, SubFilterPkcs7Detached, placeholderByteRange, contentsPlaceholder,
	)
	buf.WriteString(sigDictObjStr)

	// 3. AcroForm Object (preserving prior fields if any)
	acroFormOffset := int64(buf.Len())
	var fieldsEntry string
	if existingFields != "" {
		fieldsEntry = fmt.Sprintf("[ %s %d 0 R ]", existingFields, sigFieldObjID)
	} else {
		fieldsEntry = fmt.Sprintf("[ %d 0 R ]", sigFieldObjID)
	}

	acroFormObjStr := fmt.Sprintf(
		"%d 0 obj\n<<\n  /Fields %s\n  /SigFlags 3\n>>\nendobj\n",
		acroFormObjID, fieldsEntry,
	)
	buf.WriteString(acroFormObjStr)

	// 4. Updated Catalog Object (/Root)
	catalogOffset := int64(buf.Len())
	catalogObjStr := fmt.Sprintf(
		"%d %d obj\n<<\n  /Type /Catalog\n  /Pages %s\n  /AcroForm %d 0 R\n>>\nendobj\n",
		rootObjNum, rootGenNum, pagesRef, acroFormObjID,
	)
	buf.WriteString(catalogObjStr)

	xrefTableOffset := int64(buf.Len())

	// Build Xref section
	buf.WriteString("xref\n")
	fmt.Fprintf(&buf, "%d 1\n", rootObjNum)
	fmt.Fprintf(&buf, "%010d 00000 n \n", catalogOffset)

	fmt.Fprintf(&buf, "%d 3\n", sigFieldObjID)
	fmt.Fprintf(&buf, "%010d 00000 n \n", sigFieldOffset)
	fmt.Fprintf(&buf, "%010d 00000 n \n", sigDictOffset)
	fmt.Fprintf(&buf, "%010d 00000 n \n", acroFormOffset)

	newSize := acroFormObjID + 1
	trailerStr := fmt.Sprintf(
		"trailer\n<<\n  /Size %d\n  /Root %d %d R\n  /Prev %d\n>>\nstartxref\n%d\n%%%%EOF\n",
		newSize, rootObjNum, rootGenNum, prevStartXref, xrefTableOffset,
	)
	buf.WriteString(trailerStr)

	updatedPDF := buf.Bytes()

	finalPDF, err := finalizeByteRange(updatedPDF)
	if err != nil {
		return nil, err
	}

	return finalPDF, nil
}

// finalizeByteRange computes the exact ByteRange over the latest incremental PDF bytes and updates the placeholder.
func finalizeByteRange(pdfBytes []byte) ([]byte, error) {
	brMarker := []byte("/ByteRange ")
	idx := bytes.LastIndex(pdfBytes, brMarker)
	if idx == -1 {
		return nil, fmt.Errorf("%w: /ByteRange not found in generated PDF", ErrInvalidPDF)
	}

	startBr := idx + len(brMarker) // points to '['
	searchWindow := 60
	if startBr+searchWindow > len(pdfBytes) {
		searchWindow = len(pdfBytes) - startBr
	}
	endRel := bytes.Index(pdfBytes[startBr:startBr+searchWindow], []byte("]"))
	if endRel == -1 {
		return nil, fmt.Errorf("%w: malformed /ByteRange array", ErrInvalidPDF)
	}
	endBr := startBr + endRel

	contentsMarker := []byte("/Contents <")
	cIdx := bytes.LastIndex(pdfBytes, contentsMarker)
	if cIdx == -1 {
		return nil, fmt.Errorf("%w: /Contents < not found in generated PDF", ErrInvalidPDF)
	}

	contentsStartHex := int64(cIdx + len(contentsMarker))

	closeAngle := bytes.Index(pdfBytes[contentsStartHex:], []byte(">"))
	if closeAngle == -1 {
		return nil, fmt.Errorf("%w: /Contents closing '>' not found", ErrInvalidPDF)
	}
	contentsEndHex := contentsStartHex + int64(closeAngle)
	fileEnd := int64(len(pdfBytes))

	off1 := int64(0)
	len1 := contentsStartHex
	off2 := contentsEndHex
	len2 := fileEnd - contentsEndHex

	newByteRangeStr := fmt.Sprintf("[ %010d %010d %010d %010d ]", off1, len1, off2, len2)
	placeholderStr := string(pdfBytes[startBr : endBr+1])

	if len(newByteRangeStr) != len(placeholderStr) {
		return nil, fmt.Errorf("pdfsign: byte range string length mismatch: got %d, expected %d", len(newByteRangeStr), len(placeholderStr))
	}

	copy(pdfBytes[startBr:endBr+1], []byte(newByteRangeStr))

	return pdfBytes, nil
}

// ComputeByteRange parses the finalized PDF bytes and returns the 4-element ByteRange [off1, len1, off2, len2] for the latest signature.
func ComputeByteRange(pdfBytes []byte) ([4]int64, error) {
	ranges, err := ComputeAllByteRanges(pdfBytes)
	if err != nil {
		return [4]int64{}, err
	}
	if len(ranges) == 0 {
		return [4]int64{}, fmt.Errorf("%w: /ByteRange not found", ErrInvalidPDF)
	}
	return ranges[len(ranges)-1], nil
}

// ComputeAllByteRanges parses all /ByteRange occurrences in the PDF for multi-signature inspection.
func ComputeAllByteRanges(pdfBytes []byte) ([][4]int64, error) {
	brMarker := []byte("/ByteRange ")
	var results [][4]int64

	searchOffset := 0
	for {
		idx := bytes.Index(pdfBytes[searchOffset:], brMarker)
		if idx == -1 {
			break
		}
		actualIdx := searchOffset + idx
		startBr := actualIdx + len(brMarker)
		searchWindow := 60
		if startBr+searchWindow > len(pdfBytes) {
			searchWindow = len(pdfBytes) - startBr
		}
		endRel := bytes.Index(pdfBytes[startBr:startBr+searchWindow], []byte("]"))
		if endRel == -1 {
			searchOffset = startBr
			continue
		}
		endBr := startBr + endRel
		sub := string(pdfBytes[startBr:endBr])
		sub = strings.TrimPrefix(sub, "[")
		parts := strings.Fields(sub)
		if len(parts) == 4 {
			var br [4]int64
			valid := true
			for i := 0; i < 4; i++ {
				val, err := strconv.ParseInt(parts[i], 10, 64)
				if err != nil {
					valid = false
					break
				}
				br[i] = val
			}
			if valid {
				results = append(results, br)
			}
		}
		searchOffset = endBr + 1
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("%w: no valid /ByteRange found", ErrInvalidPDF)
	}
	return results, nil
}

// InjectSignature injects hex-encoded signature bytes into the latest /Contents slot without changing file size or offsets.
func InjectSignature(pdfBytes []byte, sigBytes []byte) ([]byte, error) {
	contentsMarker := []byte("/Contents <")
	cIdx := bytes.LastIndex(pdfBytes, contentsMarker)
	if cIdx == -1 {
		return nil, fmt.Errorf("%w: /Contents < not found", ErrInvalidPDF)
	}

	startHex := cIdx + len(contentsMarker)
	closeAngle := bytes.Index(pdfBytes[startHex:], []byte(">"))
	if closeAngle == -1 {
		return nil, fmt.Errorf("%w: /Contents closing '>' not found", ErrInvalidPDF)
	}
	endHex := startHex + closeAngle
	slotSize := endHex - startHex

	hexSig := fmt.Sprintf("%x", sigBytes)
	if int64(len(hexSig)) > int64(slotSize) {
		return nil, fmt.Errorf("pdfsign: signature too large for 16 KiB slot (%d > %d hex chars)", len(hexSig), slotSize)
	}

	paddedHex := fmt.Sprintf("%-*s", slotSize, hexSig)
	paddedHex = strings.ReplaceAll(paddedHex, " ", "0")

	out := make([]byte, len(pdfBytes))
	copy(out, pdfBytes)
	copy(out[startHex:endHex], []byte(paddedHex))

	return out, nil
}

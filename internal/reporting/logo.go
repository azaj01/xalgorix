package reporting

import (
	"image"
	// register PNG/JPEG decoders so image.DecodeConfig can validate
	// caller-supplied logo files.
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"strings"
)

// SupportedLogoExt reports whether path has an extension the report
// renderer can embed (PNG and JPEG). SVG and WebP are accepted by the
// upload pipeline but not by go-pdf/fpdf, which is why this gate is
// stricter than the upload validator.
func SupportedLogoExt(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg":
		return true
	default:
		return false
	}
}

// ValidLogo verifies that path points to a regular file with a supported
// extension and a parseable image header. It does not load the full
// pixel buffer — only the configuration block — so it is cheap to call
// from request paths.
func ValidLogo(path string) bool {
	if !SupportedLogoExt(path) {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	_, _, err = image.DecodeConfig(file)
	return err == nil
}

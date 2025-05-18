package util

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

func TerminateIfErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Function to convert from Codepage string (given as bytes) to UTF-8
func ConvertFromCodepageToUtf8(encData []byte, codePage uint16) (string, error) {
	// Select the appropriate code page decoder
	var decoder *charmap.Charmap
	switch codePage {
	case 1250: // Western European code page
		decoder = charmap.Windows1250
	case 1251: // Central European code page
		decoder = charmap.Windows1251
	case 1252: // Cyrillic code page
		decoder = charmap.Windows1252
	case 936: // Simplified Chinese code page
		decoder = charmap.CodePage037
	default:
		decoder = charmap.Windows1252
	}
	// Create a decoder and transform the bytes
	utf8Bytes, _, err := transform.Bytes(decoder.NewDecoder(), encData)
	if err != nil {
		return "", fmt.Errorf("failed to decode: %v", err)
	}

	return string(utf8Bytes), nil
}

// Function to convert UTF8 string (given as bytes) to Codepage
func ConvertUtf8ToCodepage(utf8 []byte, codePage uint16) ([]byte, error) {
	// Select the appropriate code page encoder
	var encoder *charmap.Charmap
	switch codePage {
	case 1250: // Western European code page
		encoder = charmap.Windows1250
	case 1251: // Central European code page
		encoder = charmap.Windows1251
	case 1252: // Cyrillic code page
		encoder = charmap.Windows1252
	case 936: // Simplified Chinese code page
		encoder = charmap.CodePage037
	default:
		encoder = charmap.Windows1252
	}
	// Create a encoder and transform the bytes
	encBytes, _, err := transform.Bytes(encoder.NewEncoder(), utf8)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to encode: %v", err)
	}
	return encBytes, nil
}

// parse PEM certificate
func parsePublicKey(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no key found")
	}
	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// The wide-character-string literal L"hello" becomes an array of six integers of type wchar_t
func GetFixedWidthString16(input []byte) []byte {
	inputLen := len(input)
	res := make([]byte, 0, inputLen*2)
	for i := range inputLen {
		res, _ = binary.Append(res, binary.LittleEndian, uint16(input[i]))
	}
	return res
}

func LoadPemCertificate(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(pemBytes)
}

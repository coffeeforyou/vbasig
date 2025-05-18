package vbasigfile

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
)

// VBASigSerializedCertStore represents the main structure
type VBASigSerializedCertStore struct {
	Version   uint32 // must be 0x00000000
	FileType  uint32 // must be 0x54524543
	CertGroup CertStoreCertificateGroup
	EndMarker EndElementMarkerEntry
}

// CertStoreCertificateGroup holds a list of property entries and a certificate
type CertStoreCertificateGroup struct {
	ElementList        []SerializedPropertyEntry
	CertificateElement SerializedCertificateEntry
}

// Define the structure of the binary data format.
type SerializedCertificateEntry struct {
	ID           uint32           // 4 bytes: id, must be 0x00000020
	EncodingType uint32           // 4 bytes: encodingType, must be 0x00000001
	Length       uint32           // 4 bytes: length, specifies the certificate size in bytes
	Certificate  x509.Certificate // variable length: the certificate data (DER-encoded X.509 certificate)
}

// EndElementMarkerEntry marks the end of the structure
type EndElementMarkerEntry struct {
	ID     uint32  // must be 0x00000000
	Marker [8]byte // must be all zeroes
}

func (s *VBASigSerializedCertStore) Serialize() ([]byte, error) {
	w := bytes.Buffer{}
	binary.Write(&w, binary.LittleEndian, s.Version)  // constant
	binary.Write(&w, binary.LittleEndian, s.FileType) // constant
	// not writing any SerializedPropertyEntry, could be ignored on read anyway
	binary.Write(&w, binary.LittleEndian, []byte{0x20, 0x00, 0x00, 0x00}) // entry id to start cert
	binary.Write(&w, binary.LittleEndian, []byte{0x01, 0x00, 0x00, 0x00}) // constant encoding (ASN.1)
	certLen := uint32(len(s.CertGroup.CertificateElement.Certificate.Raw))
	binary.Write(&w, binary.LittleEndian, certLen)                                                // lenght of cert bytes
	binary.Write(&w, binary.LittleEndian, s.CertGroup.CertificateElement.Certificate.Raw)         // ASN.1-encoded X.509 certificate
	binary.Write(&w, binary.LittleEndian, []byte{0x00, 0x00, 0x00, 0x00})                         // end marker id
	binary.Write(&w, binary.LittleEndian, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // end marker marker
	return w.Bytes(), nil
}

func NewVbaSigSerializedCertStore(signCert x509.Certificate) ([]byte, error) {
	res := VBASigSerializedCertStore{}
	res.Version = 0x00000000
	res.FileType = 0x54524543
	res.CertGroup.CertificateElement.Certificate = signCert
	return res.Serialize()
}

func ParseVBASigSerializedCertStore(r io.Reader) (*VBASigSerializedCertStore, error) {
	var store VBASigSerializedCertStore

	if err := binary.Read(r, binary.LittleEndian, &store.Version); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &store.FileType); err != nil {
		return nil, err
	}
	if store.FileType != 0x54524543 {
		return nil, errors.New("invalid fileType, expected 0x54524543")
	}

	// Read SerializedPropertyEntries until we hit ID 0x00000020
	for {
		var entry SerializedPropertyEntry
		if err := binary.Read(r, binary.LittleEndian, &entry.ID); err != nil {
			return nil, err
		}
		if entry.ID == 0x00000020 {
			// This is actually the certificate
			var cert SerializedCertificateEntry
			cert.ID = entry.ID
			if err := binary.Read(r, binary.LittleEndian, &cert.EncodingType); err != nil {
				return nil, err
			}
			if err := binary.Read(r, binary.LittleEndian, &cert.Length); err != nil {
				return nil, err
			}
			certBuf := make([]byte, cert.Length)
			if _, err := io.ReadFull(r, certBuf); err != nil {
				return nil, err
			}
			parsedCert, err := x509.ParseCertificate(certBuf)
			if err != nil {
				return nil, err
			}
			cert.Certificate = *parsedCert
			store.CertGroup.CertificateElement = cert
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &entry.EncodingType); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &entry.Length); err != nil {
			return nil, err
		}
		entry.Value = make([]byte, entry.Length)
		if _, err := io.ReadFull(r, entry.Value); err != nil {
			return nil, err
		}
		store.CertGroup.ElementList = append(store.CertGroup.ElementList, entry)
	}

	// Read EndElementMarkerEntry
	var endMarker EndElementMarkerEntry
	if err := binary.Read(r, binary.LittleEndian, &endMarker); err != nil {
		return nil, err
	}
	store.EndMarker = endMarker

	return &store, nil
}

// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tls13 implements the TLS 1.3 Key Schedule as specified in RFC 8446,
// Section 7.1 and allowed by FIPS 140-3 IG 2.4.B Resolution 7.
package tls13

import (
	"crypto"
	fips140 "hash"

	"github.com/refraction-networking/utls/internal/byteorder"
	"github.com/refraction-networking/utls/internal/hkdf"
)

// GetBuffer, if non-nil, is used instead of make([]byte, size) for temporary
// scratch buffers within this package. Set via the parent tls package's
// SetBufferPool.
var GetBuffer func(int) []byte

// PutBuffer, if non-nil, returns a scratch buffer obtained via GetBuffer.
var PutBuffer func([]byte)

// We don't set the service indicator in this package but we delegate that to
// the underlying functions because the TLS 1.3 KDF does not have a standard of
// its own.

// ExpandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func ExpandLabel(hash crypto.Hash, secret []byte, label string, context []byte, length int) []byte {
	if len("tls13 ")+len(label) > 255 || len(context) > 255 {
		panic("tls13: label or context too long")
	}
	labelCap := 2 + 1 + len("tls13 ") + len(label) + 1 + len(context)
	var hkdfLabel []byte
	if GetBuffer != nil {
		hkdfLabel = GetBuffer(labelCap)[:0]
	} else {
		hkdfLabel = make([]byte, 0, labelCap)
	}
	hkdfLabel = byteorder.BEAppendUint16(hkdfLabel, uint16(length))
	hkdfLabel = append(hkdfLabel, byte(len("tls13 ")+len(label)))
	hkdfLabel = append(hkdfLabel, "tls13 "...)
	hkdfLabel = append(hkdfLabel, label...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)
	result := hkdf.Expand(hash, secret, string(hkdfLabel), length)
	if PutBuffer != nil {
		PutBuffer(hkdfLabel)
	}
	return result
}

func extract(hash crypto.Hash, newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, hash.Size())
	}
	return hkdf.Extract(hash, newSecret, currentSecret)
}

// emptySHA256 is SHA-256(""), the hash of the empty string.
var emptySHA256 = [32]byte{
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
}

// emptySHA384 is SHA-384(""), the hash of the empty string.
var emptySHA384 = [48]byte{
	0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
	0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
	0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
	0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
	0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
	0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
}

// emptyHash returns the digest of the empty string for the given hash function.
// The returned slice aliases a global read-only array — do not modify it.
func emptyHash(h crypto.Hash) []byte {
	switch h {
	case crypto.SHA256:
		return emptySHA256[:]
	case crypto.SHA384:
		return emptySHA384[:]
	default:
		panic("tls13: unsupported hash")
	}
}

func deriveSecret(hash crypto.Hash, secret []byte, label string, transcript fips140.Hash) []byte {
	if transcript == nil {
		return ExpandLabel(hash, secret, label, emptyHash(hash), hash.Size())
	}
	return ExpandLabel(hash, secret, label, transcript.Sum(nil), transcript.Size())
}

const (
	resumptionBinderLabel         = "res binder"
	clientEarlyTrafficLabel       = "c e traffic"
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	earlyExporterLabel            = "e exp master"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
)

type EarlySecret struct {
	secret []byte
	hash   crypto.Hash
}

func NewEarlySecret(hash crypto.Hash, psk []byte) *EarlySecret {
	return &EarlySecret{
		secret: extract(hash, psk, nil),
		hash:   hash,
	}
}

func (s *EarlySecret) ResumptionBinderKey() []byte {
	return deriveSecret(s.hash, s.secret, resumptionBinderLabel, nil)
}

// ClientEarlyTrafficSecret derives the client_early_traffic_secret from the
// early secret and the transcript up to the ClientHello.
func (s *EarlySecret) ClientEarlyTrafficSecret(transcript fips140.Hash) []byte {
	return deriveSecret(s.hash, s.secret, clientEarlyTrafficLabel, transcript)
}

type HandshakeSecret struct {
	secret []byte
	hash   crypto.Hash
}

func (s *EarlySecret) HandshakeSecret(sharedSecret []byte) *HandshakeSecret {
	derived := deriveSecret(s.hash, s.secret, "derived", nil)
	return &HandshakeSecret{
		secret: extract(s.hash, sharedSecret, derived),
		hash:   s.hash,
	}
}

// ClientHandshakeTrafficSecret derives the client_handshake_traffic_secret from
// the handshake secret and the transcript up to the ServerHello.
func (s *HandshakeSecret) ClientHandshakeTrafficSecret(transcript fips140.Hash) []byte {
	return deriveSecret(s.hash, s.secret, clientHandshakeTrafficLabel, transcript)
}

// ServerHandshakeTrafficSecret derives the server_handshake_traffic_secret from
// the handshake secret and the transcript up to the ServerHello.
func (s *HandshakeSecret) ServerHandshakeTrafficSecret(transcript fips140.Hash) []byte {
	return deriveSecret(s.hash, s.secret, serverHandshakeTrafficLabel, transcript)
}

type MasterSecret struct {
	secret []byte
	hash   crypto.Hash
}

func (s *HandshakeSecret) MasterSecret() *MasterSecret {
	derived := deriveSecret(s.hash, s.secret, "derived", nil)
	return &MasterSecret{
		secret: extract(s.hash, nil, derived),
		hash:   s.hash,
	}
}

// ClientApplicationTrafficSecret derives the client_application_traffic_secret_0
// from the master secret and the transcript up to the server Finished.
func (s *MasterSecret) ClientApplicationTrafficSecret(transcript fips140.Hash) []byte {
	return deriveSecret(s.hash, s.secret, clientApplicationTrafficLabel, transcript)
}

// ServerApplicationTrafficSecret derives the server_application_traffic_secret_0
// from the master secret and the transcript up to the server Finished.
func (s *MasterSecret) ServerApplicationTrafficSecret(transcript fips140.Hash) []byte {
	return deriveSecret(s.hash, s.secret, serverApplicationTrafficLabel, transcript)
}

// ResumptionMasterSecret derives the resumption_master_secret from the master secret
// and the transcript up to the client Finished.
func (s *MasterSecret) ResumptionMasterSecret(transcript fips140.Hash) []byte {
	return deriveSecret(s.hash, s.secret, resumptionLabel, transcript)
}

type ExporterMasterSecret struct {
	secret []byte
	hash   crypto.Hash
}

// ExporterMasterSecret derives the exporter_master_secret from the master secret
// and the transcript up to the server Finished.
func (s *MasterSecret) ExporterMasterSecret(transcript fips140.Hash) *ExporterMasterSecret {
	return &ExporterMasterSecret{
		secret: deriveSecret(s.hash, s.secret, exporterLabel, transcript),
		hash:   s.hash,
	}
}

// EarlyExporterMasterSecret derives the exporter_master_secret from the early secret
// and the transcript up to the ClientHello.
func (s *EarlySecret) EarlyExporterMasterSecret(transcript fips140.Hash) *ExporterMasterSecret {
	return &ExporterMasterSecret{
		secret: deriveSecret(s.hash, s.secret, earlyExporterLabel, transcript),
		hash:   s.hash,
	}
}

func (s *ExporterMasterSecret) Exporter(label string, context []byte, length int) []byte {
	secret := deriveSecret(s.hash, s.secret, label, nil)
	h := s.hash.New()
	h.Write(context)
	return ExpandLabel(s.hash, secret, "exporter", h.Sum(nil), length)
}

func TestingOnlyExporterSecret(s *ExporterMasterSecret) []byte {
	return s.secret
}

package tls13

import "crypto"

func NewEarlySecretFromSecret(hash crypto.Hash, secret []byte) *EarlySecret {
	return &EarlySecret{
		secret: secret,
		hash:   hash,
	}
}

func (s *EarlySecret) Secret() []byte {
	if s != nil {
		return s.secret
	}
	return nil
}

func NewMasterSecretFromSecret(hash crypto.Hash, secret []byte) *MasterSecret {
	return &MasterSecret{
		secret: secret,
		hash:   hash,
	}
}

func (s *MasterSecret) Secret() []byte {
	if s != nil {
		return s.secret
	}
	return nil
}

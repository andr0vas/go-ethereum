package keeper

import (
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// PrivateKeyKeeper is layer for protecting private key from direct using.
type PrivateKeyKeeper interface {
	// GeneratePrivateKey return identifier of new generated private key
	GeneratePrivateKey() (prvID []byte, err error)
	// GetPublicKey return public key by private key ID
	GetPublicKey(prvID []byte) ([]byte, error)
	// Sign of data by private key ID
	Sign(data []byte, prvID []byte) ([]byte, error)
}

// defaultKeeper realized interface PrivateKeyKeeper without hiding the private key
var defaultKeeper PrivateKeyKeeper = &defaultPrivateKeyKeeper{}

type defaultPrivateKeyKeeper struct {
}

func (a *defaultPrivateKeyKeeper) GeneratePrivateKey() ([]byte, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	return privateKeyBytes, nil
}

func (a *defaultPrivateKeyKeeper) GetPublicKey(prvID []byte) ([]byte, error) {
	privateKey, err := crypto.ToECDSA(prvID)
	if err != nil {
		return nil, err
	}
	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("cannot cast public key to ecsda public key")
	}
	return crypto.FromECDSAPub(publicKeyECDSA), nil
}

func (a *defaultPrivateKeyKeeper) Sign(data []byte, prvID []byte) ([]byte, error) {
	prv, err := crypto.ToECDSA(prvID)
	if err != nil {
		return nil, err
	}
	sig, err := crypto.Sign(data, prv)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

type SecureSign struct {
	keeper PrivateKeyKeeper
}

func (a *SecureSign) SetKeeper(keeper PrivateKeyKeeper) {
	a.keeper = keeper
}

func (a *SecureSign) Sign(tx *types.Transaction, s types.Signer, prvID []byte) (*types.Transaction, error) {
	if a.keeper == nil {
		a.keeper = defaultKeeper
	}
	h := s.Hash(tx)
	sig, err := a.keeper.Sign(h[:], prvID)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

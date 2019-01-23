package waddrmgr

import (
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/walletdb"
)

type KeyMaker interface {
	CreateMasterKey() (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error)

	// deriveCoinTypeKey derives the cointype key which can be used to derive the
	// extended key for an account according to the hierarchy described by BIP0044
	// given the coin type key.
	//
	// In particular this is the hierarchical deterministic extended key path:
	// m/purpose'/<coin type>'
	DeriveCoinTypeKey(scope KeyScope, ns walletdb.ReadWriteBucket, cryptoKeyPriv EncryptorDecryptor) (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error)

	// deriveAccountKey derives the extended key for an account according to the
	// hierarchy described by BIP0044 given the master node.
	//
	// In particular this is the hierarchical deterministic extended key path:
	//   m/purpose'/<coin type>'/<account>'
	DeriveAccountKey(scope KeyScope, account uint32, ns walletdb.ReadWriteBucket, cryptoKeyPriv EncryptorDecryptor) (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error)
}

type LocalKeyMaker struct {
	seed []byte
	chainParams *chaincfg.Params
	rootPrivKey *hdkeychain.ExtendedKey
	manager *Manager
}

func NewLocalKeyMaker(rootPrivKey *hdkeychain.ExtendedKey) (KeyMaker, error) {
	return &LocalKeyMaker{rootPrivKey: rootPrivKey}, nil
}

func NewLocalKeyMakerFromSeed(seed []byte, chainParams *chaincfg.Params) KeyMaker {
	return &LocalKeyMaker{seed: seed, chainParams: chainParams}
}

func (s *LocalKeyMaker) CreateMasterKey() (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error) {
	rootPrivKey, err := hdkeychain.NewMaster(s.seed, s.chainParams)
	if err != nil {
		str := "failed to derive master extended key"
		return nil, nil, errors.New(str)
	}
	rootPubKey, err := rootPrivKey.Neuter()
	if err != nil {
		str := "failed to neuter master extended key"
		return nil, nil, errors.New(str)
	}

	s.rootPrivKey = rootPrivKey

	return rootPrivKey, rootPubKey, nil
}

func (s *LocalKeyMaker) DeriveCoinTypeKey(scope KeyScope, ns walletdb.ReadWriteBucket, cryptoKeyPriv EncryptorDecryptor) (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error) {
	// Enforce maximum coin type.
	if scope.Coin > maxCoinType {
		err := managerError(ErrCoinTypeTooHigh, errCoinTypeTooHigh, nil)
		return nil, nil, err
	}

	if s.rootPrivKey == nil {
		masterRootPrivEnc, _, err := fetchMasterHDKeys(ns)
		if err != nil {
			return nil, nil, err
		}

		// If the master root private key isn't found within the database, but
		// we need to bail here as we can't create the cointype key without the
		// master root private key.
		if masterRootPrivEnc == nil {
			return nil, nil, managerError(ErrWatchingOnly, "", nil)
		}

		// Before we can derive any new scoped managers using this key, we'll
		// need to fully decrypt it.
		serializedMasterRootPriv, err := cryptoKeyPriv.Decrypt(masterRootPrivEnc)
		if err != nil {
			str := fmt.Sprintf("failed to decrypt master root serialized private key")
			return nil, nil, managerError(ErrLocked, str, err)
		}

		// Now that we know the root priv is within the database, we'll decode
		// it into a usable object.
		s.rootPrivKey, err = hdkeychain.NewKeyFromString(
			string(serializedMasterRootPriv),
		)
		zero.Bytes(serializedMasterRootPriv)
		if err != nil {
			str := fmt.Sprintf("failed to create master extended private key")
			return nil, nil, managerError(ErrKeyChain, str, err)
		}

	}
	// The hierarchy described by BIP0043 is:
	//  m/<purpose>'/*
	//
	// This is further extended by BIP0044 to:
	//  m/44'/<coin type>'/<account>'/<branch>/<address index>
	//
	// However, as this is a generic key store for any family for BIP0044
	// standards, we'll use the custom scope to govern our key derivation.
	//
	// The branch is 0 for external addresses and 1 for internal addresses.

	// Derive the purpose key as a child of the master node.
	purpose, err := s.rootPrivKey.Child(scope.Purpose + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, nil, err
	}

	// Derive the coin type key as a child of the purpose key.
	coinTypePrivKey, err := purpose.Child(scope.Coin + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, nil, err
	}

	coinTypePubKey, err := coinTypePrivKey.Neuter()
	if err != nil {
		str := "failed to convert cointype private key"
		return nil, nil, errors.New(str)
	}

	return coinTypePrivKey, coinTypePubKey, nil
}

func (s *LocalKeyMaker) DeriveAccountKey(scope KeyScope, account uint32, ns walletdb.ReadWriteBucket, cryptoKeyPriv EncryptorDecryptor) (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error) {
	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, nil, err
	}

	coinTypePrivKey, _, err := s.DeriveCoinTypeKey(scope, ns, cryptoKeyPriv)
	// Derive the account key as a child of the coin type key.
	acctKeyPriv, err := coinTypePrivKey.Child(account + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, nil, err
	}

	acctKeyPub, err := acctKeyPriv.Neuter()
	if err != nil {
		str := "failed to convert private key for account 0"
		return nil, nil, errors.New(str)
	}

	return acctKeyPriv, acctKeyPub, nil
}

type RemoteKeyMaker struct {
	hwConfig *HwConfig
}

func NewRemoteKeyMaker(hwConfig *HwConfig) (KeyMaker, error) {
	return &RemoteKeyMaker{ hwConfig: hwConfig}, nil
}

func (s *RemoteKeyMaker) CreateMasterKey() (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error) {
	panic("implement me")
}

func (s *RemoteKeyMaker) DeriveCoinTypeKey(scope KeyScope, ns walletdb.ReadWriteBucket, cryptoKeyPriv EncryptorDecryptor) (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error) {
	panic("implement me")
}

func (s *RemoteKeyMaker) DeriveAccountKey(scope KeyScope, account uint32, ns walletdb.ReadWriteBucket, cryptoKeyPriv EncryptorDecryptor) (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error) {
	panic("implement me")
}

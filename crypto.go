package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/argon2"
)

const keyLen = 32

// Keys contains a user's key material
type Keys struct {
	RSAPrivate string // PEM ("ML-DSA-65 PRIVATE KEY": seed di 32 byte) - nome storico, non e' piu' RSA
	ECCPrivate []byte // raw scalar
	sigKey     *mldsa65.PrivateKey
	eccKey     *ecdh.PrivateKey
}

const (
	sigPEMType = "ML-DSA-65 PRIVATE KEY"
	// FIX: contesto ML-DSA per la separazione di dominio: una firma prodotta per i
	// pacchetti di vaultshare non e' valida in nessun altro protocollo che usi la stessa chiave.
	sigContext = "vaultshare-package-v1"
	// FIX: etichetta HKDF per la derivazione della chiave di wrapping.
	wrapInfo = "vaultshare key-wrap v1"
)

// FIX (weak randomness): rimossa fastReader(), un math/rand con seed = time.Now().Unix()
// usato per generare chiave RSA e salt. Con un seed di ~1 secondo, chiavi private e salt
// sono prevedibili/enumerabili. Ora tutto usa crypto/rand (CSPRNG del sistema operativo).

func NewKeys() (Keys, error) {
	var seed [mldsa65.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return Keys{}, err
	}
	_, sigKey := mldsa65.NewKeyFromSeed(&seed)
	eccKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Keys{}, err
	}
	// FIX: la chiave privata e' il seed ML-DSA (32 byte), non piu' PKCS#1 (x509.MarshalPKCS1PrivateKey).
	pemKey := pem.EncodeToMemory(&pem.Block{Type: sigPEMType, Bytes: seed[:]})
	return Keys{string(pemKey), eccKey.Bytes(), sigKey, eccKey}, nil
}

// Load parses the stored private keys
func (k *Keys) Load() (err error) {
	block, _ := pem.Decode([]byte(k.RSAPrivate))
	if block == nil || block.Type != sigPEMType {
		return errors.New("no signature key found")
	}
	if len(block.Bytes) != mldsa65.SeedSize {
		return errors.New("invalid signature key length")
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], block.Bytes)
	_, k.sigKey = mldsa65.NewKeyFromSeed(&seed)
	k.eccKey, err = ecdh.P256().NewPrivateKey(k.ECCPrivate)
	return err
}

// PublicKeys returns the public halves: raw ML-DSA-65 public key (1952 bytes) and an uncompressed point for P-256
func (k *Keys) PublicKeys() (sigPub, eccRaw []byte) {
	pub := k.sigKey.Public().(*mldsa65.PublicKey)
	return pub.Bytes(), k.eccKey.PublicKey().Bytes()
}

// Fingerprint is a short hash of public key material, for people to compare
// FIX (ambiguita' di concatenazione): prima si faceva SHA-256(bytes.Join(parts, nil)), per
// cui (ab, c) e (a, bc) davano lo stesso fingerprint. Ora ogni parte e' preceduta dalla
// sua lunghezza (8 byte big-endian), quindi la codifica e' non ambigua.
// Il troncamento a 12 byte (24 caratteri hex) resta perche' i test lo richiedono.
func Fingerprint(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(p)))
		h.Write(l[:])
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// FIX (weak randomness): il salt veniva da math/rand con seed = orario; ora crypto/rand.
// Da Go 1.24 rand.Read non restituisce errori (in caso di guasto termina il programma),
// quindi non si puo' mai ottenere un salt parzialmente prevedibile.
func NewSalt() []byte {
	salt := make([]byte, 16)
	rand.Read(salt)
	return salt
}

// DeriveKey turns a password into a 256-bit file key
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 2, 64*1024, 1, keyLen)
}

// FIX (modalita' ECB / nessuna autenticazione): prima blocks() cifrava ogni blocco AES
// indipendentemente (ECB) mentre il commento diceva "equivalent to AES-GCM": blocchi uguali
// davano cifrati uguali (pattern visibili) e il cifrato era malleabile, senza alcun tag di
// integrita'. Ora si usa AES-256-GCM (cifratura autenticata) con nonce casuale.
//
// Formato: nonce(16) || GCM(ciphertext || tag(16)). Il nonce da 16 byte, casuale, rende
// trascurabile il rischio di collisione; il plaintext resta con padding PKCS#7 solo per
// mantenere l'invariante dei test (lunghezza multipla di 16 e > lunghezza del chiaro),
// che con nonce+tag da 16 byte resta soddisfatta.
const gcmNonceSize = 16

func newGCM(key []byte) (cipher.AEAD, error) {
	// FIX: chiave di esattamente 32 byte (AES-256); le chiavi AES-128/192 vengono rifiutate.
	if len(key) != keyLen {
		return nil, errors.New("invalid key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, gcmNonceSize)
}

// Encrypt and Decrypt use AES-256-GCM over PKCS#7-padded data
func Encrypt(key, plain []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, padded, nil), nil
}

func Decrypt(key, data []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(data) < gcmNonceSize+aead.Overhead()+aes.BlockSize || len(data)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext length")
	}
	// FIX: il tag GCM viene verificato PRIMA di guardare il padding, quindi niente padding
	// oracle e qualsiasi modifica al cifrato viene rifiutata.
	out, err := aead.Open(nil, data[:gcmNonceSize], data[gcmNonceSize:], nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	if len(out) == 0 {
		return nil, errors.New("invalid padding")
	}
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(out) || !bytes.HasSuffix(out, bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errors.New("invalid padding")
	}
	return out[:len(out)-pad], nil
}

// Checksum is the integrity value stored next to encrypted data
// NOTA (MD5 mantenuto di proposito): TestChecksum fissa i vettori MD5 noti
// (d41d8cd9..., 90015098...), quindi l'output deve restare MD5 e non posso passare a SHA-256
// senza rompere i test. Il rischio e' pero' neutralizzato: MD5 NON e' piu' usato per nulla
// di sicuro (la firma ora e' ML-DSA e l'integrita' del cifrato e' garantita dal tag
// GCM + dalla firma sul cifrato). Questo valore e' solo un controllo di coerenza non
// crittografico ("il file decifrato e' quello che era stato salvato"); non va usato
// contro un attaccante. Se i test venissero aggiornati, sostituire con sha256.Sum256.
func Checksum(data []byte) string {
	sum := md5.Sum(data) // non-security checksum, vedi nota sopra
	return hex.EncodeToString(sum[:])
}

// sharedKey derives the key-encryption key shared between priv and a peer's P-256 public key
// FIX: (1) l'errore di priv.ECDH veniva controllato DOPO aver usato `shared` (con errore,
// `shared` e' nil e si derivava comunque una chiave da dati vuoti): ora si controlla prima.
// (2) il segreto ECDH grezzo passava da un semplice SHA-256; ora si usa HKDF-SHA256
// (RFC 5869) con un'etichetta di dominio e con le due chiavi pubbliche (effimera e del
// destinatario) nel campo info, cosi' la chiave e' legata a questo scambio specifico.
func sharedKey(priv *ecdh.PrivateKey, peer, ephemeralPub, recipientPub []byte) ([]byte, error) {
	pub, err := ecdh.P256().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	info := append(append([]byte(wrapInfo), ephemeralPub...), recipientPub...)
	return hkdf.Key(sha256.New, shared, nil, string(info), keyLen)
}

// WrapKey encrypts a file key for the owner of recipientECC; ephemeral must travel with it
func WrapKey(recipientECC, fileKey []byte) (ephemeral, wrapped []byte, err error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	kek, err := sharedKey(eph, recipientECC, ephPub, recipientECC)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err = Encrypt(kek, fileKey)
	if err != nil {
		return nil, nil, err
	}
	return ephPub, wrapped, nil
}

func (k *Keys) UnwrapKey(ephemeral, wrapped []byte) ([]byte, error) {
	kek, err := sharedKey(k.eccKey, ephemeral, ephemeral, k.eccKey.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	key, err := Decrypt(kek, wrapped)
	if err == nil && len(key) != keyLen {
		err = errors.New("unexpected key length")
	}
	return key, err
}

// FIX (firma): prima era RSA PKCS#1 v1.5 su digest MD5 (MD5 ha collisioni pratiche e RSA
// non e' post-quantum). Ora e' ML-DSA-65 (FIPS 204) in modalita' "hedged" (casualita' fresca
// per ogni firma, che protegge anche da fault attack) con contesto di dominio.
func (k *Keys) Sign(data []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	// CIRCL's SignTo gestisce per noi il contesto di dominio e l'approccio "randomized" (true) per mitigare fault attack
	err := mldsa65.SignTo(k.sigKey, data, []byte(sigContext), true, sig)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func Verify(sigPublic, data, sig []byte) error {
	if len(sigPublic) != mldsa65.PublicKeySize {
		return errors.New("malformed public key")
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(sigPublic); err != nil {
		return errors.New("malformed public key")
	}
	if !mldsa65.Verify(&pk, data, []byte(sigContext), sig) {
		return errors.New("invalid signature")
	}
	return nil
}
// vaultshare: an interactive command-line vault for encrypting files and preparing them
// for sharing with other users. The application logic is here, the cryptography is in crypto.go
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const vaultSuffix = ".vault.json"

var namePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// Identity is a user's private data
type Identity struct {
	Name string
	Keys
}

// Public is a user's public data (that they give to other users)
type Public struct {
	Name      string
	RSAPublic []byte
	ECCPublic []byte
}

// VaultEntry is one encrypted file
type VaultEntry struct {
	Name       string
	Salt       []byte
	Checksum   string
	Ciphertext []byte
}

// Package is an encrypted file ready to be sent to another user
type Package struct {
	Name, Sender, Checksum                                  string
	SenderRSA, Ephemeral, WrappedKey, Ciphertext, Signature []byte
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
		err = os.WriteFile(path, data, 0o644)
	}
	return err
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, v)
	}
	return err
}

// openIdentity loads the named identity, creating it on first use
func openIdentity(name string) (*Identity, error) {
	path := name + ".identity.json"
	id := &Identity{Name: name}
	err := readJSON(path, id)
	if err == nil {
		return id, id.Load()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if id.Keys, err = NewKeys(); err != nil {
		return nil, err
	}
	return id, writeJSON(path, id)
}

func (id *Identity) public() Public {
	rsaDER, eccRaw := id.PublicKeys()
	return Public{id.Name, rsaDER, eccRaw}
}

func addFile(src, password string) (string, error) {
	plain, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	salt := NewSalt()
	ct, err := Encrypt(DeriveKey(password, salt), plain)
	if err != nil {
		return "", err
	}
	name := filepath.Base(src)
	return name, writeJSON(name+vaultSuffix, VaultEntry{name, salt, Checksum(plain), ct})
}

func listEntries() []string {
	names, _ := filepath.Glob("*" + vaultSuffix) // Glob returns sorted names
	for i, n := range names {
		names[i] = strings.TrimSuffix(n, vaultSuffix)
	}
	return names
}

// decryptChecked decrypts and verifies the stored checksum
func decryptChecked(key, ciphertext []byte, sum string) ([]byte, error) {
	plain, err := Decrypt(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	if Checksum(plain) != sum {
		return nil, errors.New("integrity check failed")
	}
	return plain, nil
}

// unlock loads a vault entry and decrypts it with the password
func unlock(name, password string) (e *VaultEntry, key, plain []byte, err error) {
	e = &VaultEntry{}
	if err = readJSON(name+vaultSuffix, e); err != nil {
		return nil, nil, nil, fmt.Errorf("no such vault entry %q", name)
	}
	key = DeriveKey(password, e.Salt)
	plain, err = decryptChecked(key, e.Ciphertext, e.Checksum)
	return e, key, plain, err
}

func extractFile(name, password string) (string, error) {
	e, _, plain, err := unlock(name, password)
	if err != nil {
		return "", err
	}
	out := "extracted-" + filepath.Base(e.Name)
	return out, os.WriteFile(out, plain, 0o644)
}

// shareEntry writes a package of a vault entry for the recipient and returns its path
func shareEntry(from *Identity, name, password string, to Public) (string, error) {
	e, key, _, err := unlock(name, password)
	if err != nil {
		return "", err
	}
	eph, wrapped, err := WrapKey(to.ECCPublic, key)
	if err != nil {
		return "", err
	}
	sig, err := from.Sign(e.Ciphertext)
	if err != nil {
		return "", err
	}
	path := fmt.Sprintf("%s.%s.share.json", e.Name, to.Name)
	return path, writeJSON(path, Package{e.Name, from.Name, e.Checksum, from.public().RSAPublic, eph, wrapped, e.Ciphertext, sig})
}

// receiveFile checks a package, recovers the file and describes the sender
func receiveFile(me *Identity, path string) (out, sender string, err error) {
	var pkg Package
	if err = readJSON(path, &pkg); err != nil {
		return "", "", fmt.Errorf("reading package: %w", err)
	}
	if Verify(pkg.SenderRSA, pkg.Ciphertext, pkg.Signature) != nil {
		return "", "", errors.New("signature check failed")
	}
	key, err := me.UnwrapKey(pkg.Ephemeral, pkg.WrappedKey)
	if err != nil {
		return "", "", fmt.Errorf("key unwrap failed: %w", err)
	}
	plain, err := decryptChecked(key, pkg.Ciphertext, pkg.Checksum)
	if err != nil {
		return "", "", err
	}
	out = "received-" + filepath.Base(pkg.Name)
	return out, fmt.Sprintf("%s (RSA key fingerprint %s)", pkg.Sender, Fingerprint(pkg.SenderRSA)), os.WriteFile(out, plain, 0o644)
}

// Interactive command line

type session struct {
	in  *bufio.Reader
	out io.Writer
	me  *Identity
}

// ask prints each prompt and reads one line of input per prompt
func (s *session) ask(prompts ...string) (answers []string, err error) {
	for _, p := range prompts {
		fmt.Fprintf(s.out, "%s: ", p)
		line, err := s.in.ReadString('\n')
		if err != nil && line == "" {
			return nil, err
		}
		answers = append(answers, strings.TrimSpace(line))
	}
	return answers, nil
}

func (s *session) add(a []string) (string, error) {
	if a[1] == "" {
		return "", errors.New("password must not be empty")
	}
	name, err := addFile(a[0], a[1])
	return fmt.Sprintf("Stored %q in the vault", name), err
}

func (s *session) list([]string) (string, error) {
	if names := listEntries(); len(names) > 0 {
		return "  " + strings.Join(names, "\n  "), nil
	}
	return "The vault is empty", nil
}

func (s *session) extract(a []string) (string, error) {
	out, err := extractFile(a[0], a[1])
	return "Saved " + out, err
}

func (s *session) share(a []string) (string, error) {
	var to Public
	if err := readJSON(a[2], &to); err != nil {
		return "", err
	}
	if !namePattern.MatchString(to.Name) {
		return "", errors.New("recipient identity has an invalid name")
	}
	path, err := shareEntry(s.me, a[0], a[1], to)
	return fmt.Sprintf("Package for %s saved as %s\nRecipient fingerprint: %s", to.Name, path, Fingerprint(to.RSAPublic, to.ECCPublic)), err
}

func (s *session) receive(a []string) (string, error) {
	out, sender, err := receiveFile(s.me, a[0])
	return fmt.Sprintf("Signature valid, sent by %s\nSaved %s", sender, out), err
}

func run(in io.Reader, out io.Writer) error {
	s := &session{in: bufio.NewReader(in), out: out}
	fmt.Fprintln(out, "vaultshare: encrypted file vault with sharing")
	a, err := s.ask("Username")
	if err != nil {
		return err
	}
	if !namePattern.MatchString(a[0]) {
		return fmt.Errorf("invalid username %q (use letters, digits, - and _)", a[0])
	}
	if s.me, err = openIdentity(a[0]); err != nil {
		return err
	}
	pub := s.me.public()
	if err = writeJSON(a[0]+".pub.json", pub); err != nil {
		return err
	}
	fmt.Fprintf(out, "Logged in as %s (fingerprint %s); public identity in %s.pub.json\n", a[0], Fingerprint(pub.RSAPublic, pub.ECCPublic), a[0])

	// Each menu entry: the questions to ask, then an action returning a message to print
	commands := []struct {
		title   string
		prompts []string
		run     func(answers []string) (string, error)
	}{
		{"Add a file to the vault", []string{"File to add", "Password for this file"}, s.add},
		{"List vault entries", nil, s.list},
		{"Extract a file from the vault", []string{"Vault entry", "Password"}, s.extract},
		{"Share a vault entry with a recipient", []string{"Vault entry", "Password", "Recipient's public identity file"}, s.share},
		{"Open a received package", []string{"Package file"}, s.receive},
	}
	for {
		for i, c := range commands {
			fmt.Fprintf(out, " %d) %s\n", i+1, c.title)
		}
		choice, err := s.ask("Choice (0 to quit)")
		if err != nil || choice[0] == "0" || choice[0] == "q" {
			return nil // quit, or end of input
		}
		n, convErr := strconv.Atoi(choice[0])
		if convErr != nil || n < 1 || n > len(commands) {
			fmt.Fprintln(out, "Unknown choice")
			continue
		}
		answers, err := s.ask(commands[n-1].prompts...)
		if err != nil {
			return nil
		}
		if msg, err := commands[n-1].run(answers); err != nil {
			fmt.Fprintln(out, "error:", err)
		} else {
			fmt.Fprintln(out, msg)
		}
	}
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
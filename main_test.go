package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// workdir moves the test into an empty temporary directory, since the program works in the current one
func workdir(t *testing.T) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

func write(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func user(t *testing.T, name string) *Identity {
	t.Helper()
	id, err := openIdentity(name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// script runs the interactive program on the given input lines and returns what it printed
func script(t *testing.T, lines ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatalf("run: %v\noutput:\n%s", err, out.String())
	}
	return out.String()
}

func TestOpenIdentityCreatesAndReloads(t *testing.T) {
	workdir(t)
	first := user(t, "alice")
	if _, err := os.Stat("alice.identity.json"); err != nil {
		t.Fatal("identity file was not written")
	}
	again := user(t, "alice")
	if first.public().Name != again.public().Name || !bytes.Equal(first.public().ECCPublic, again.public().ECCPublic) {
		t.Error("reloaded identity differs from the created one")
	}
}

func TestOpenIdentityRejectsCorruptFile(t *testing.T) {
	workdir(t)
	write(t, "alice.identity.json", "this is not json")
	if _, err := openIdentity("alice"); err == nil {
		t.Error("expected an error for a corrupt identity file")
	}
	write(t, "bob.identity.json", `{"Name":"bob"}`)
	if _, err := openIdentity("bob"); err == nil {
		t.Error("expected an error for an identity without keys")
	}
}

func TestAddListExtract(t *testing.T) {
	workdir(t)
	write(t, "notes.txt", "meeting notes: remember the budget review on Thursday")
	write(t, "a.txt", "first")

	if name, err := addFile("notes.txt", "pw1"); err != nil || name != "notes.txt" {
		t.Fatalf("addFile: %q, %v", name, err)
	}
	if _, err := addFile("a.txt", "pw2"); err != nil {
		t.Fatal(err)
	}
	if got := listEntries(); strings.Join(got, ",") != "a.txt,notes.txt" {
		t.Errorf("listEntries = %v", got)
	}

	out, err := extractFile("notes.txt", "pw1")
	if err != nil || out != "extracted-notes.txt" {
		t.Fatalf("extractFile: %q, %v", out, err)
	}
	if got := mustRead(t, out); got != "meeting notes: remember the budget review on Thursday" {
		t.Errorf("extracted content = %q", got)
	}
}

func TestStoredEntryHoldsEncryptedData(t *testing.T) {
	workdir(t)
	plain := strings.Repeat("confidential content ", 10)
	write(t, "secret.txt", plain)
	if _, err := addFile("secret.txt", "pw"); err != nil {
		t.Fatal(err)
	}
	var e VaultEntry
	if err := readJSON("secret.txt.vault.json", &e); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(e.Ciphertext, []byte(plain)) || strings.Contains(mustRead(t, "secret.txt.vault.json"), "confidential") {
		t.Error("plaintext found in the stored entry")
	}
	if e.Checksum != Checksum([]byte(plain)) || len(e.Salt) == 0 {
		t.Error("stored entry is missing its checksum or salt")
	}
}

func TestExtractFailures(t *testing.T) {
	workdir(t)
	write(t, "f.txt", "some file content that is long enough")
	if _, err := addFile("f.txt", "right"); err != nil {
		t.Fatal(err)
	}
	if _, err := extractFile("f.txt", "wrong"); err == nil {
		t.Error("wrong password was accepted")
	}
	if _, err := os.Stat("extracted-f.txt"); err == nil {
		t.Error("a file was written despite the wrong password")
	}
	if _, err := extractFile("missing", "right"); err == nil || !strings.Contains(err.Error(), "no such vault entry") {
		t.Errorf("missing entry: %v", err)
	}
	if _, err := addFile("nope.txt", "pw"); err == nil {
		t.Error("adding a missing file succeeded")
	}
}

func TestExtractDetectsModifiedEntry(t *testing.T) {
	workdir(t)
	write(t, "f.txt", "content of the file, a couple of blocks long")
	addFile("f.txt", "pw")
	var e VaultEntry
	readJSON("f.txt.vault.json", &e)
	e.Checksum = Checksum([]byte("something else"))
	writeJSON("f.txt.vault.json", e)
	if _, err := extractFile("f.txt", "pw"); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Errorf("expected an integrity error, got %v", err)
	}
}

// shareFile adds a file as alice and returns the package she prepares for bob
func shareFile(t *testing.T, alice *Identity, bob Public) string {
	t.Helper()
	write(t, "report.txt", "quarterly report: numbers for the whole team")
	if _, err := addFile("report.txt", "pw"); err != nil {
		t.Fatal(err)
	}
	path, err := shareEntry(alice, "report.txt", "pw", bob)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestShareAndReceive(t *testing.T) {
	workdir(t)
	alice, bob := user(t, "alice"), user(t, "bob")
	path := shareFile(t, alice, bob.public())
	if path != "report.txt.bob.share.json" {
		t.Errorf("package path = %q", path)
	}

	out, sender, err := receiveFile(bob, path)
	if err != nil {
		t.Fatal(err)
	}
	if out != "received-report.txt" || !strings.HasPrefix(sender, "alice") {
		t.Errorf("out %q, sender %q", out, sender)
	}
	if got := mustRead(t, out); got != "quarterly report: numbers for the whole team" {
		t.Errorf("received content = %q", got)
	}
}

func TestShareNeedsTheRightPassword(t *testing.T) {
	workdir(t)
	alice, bob := user(t, "alice"), user(t, "bob")
	shareFile(t, alice, bob.public())
	if _, err := shareEntry(alice, "report.txt", "wrong", bob.public()); err == nil {
		t.Error("shared with the wrong password")
	}
	if _, err := shareEntry(alice, "missing", "pw", bob.public()); err == nil {
		t.Error("shared a missing entry")
	}
}

func TestOnlyTheRecipientCanReceive(t *testing.T) {
	workdir(t)
	alice, bob, carol := user(t, "alice"), user(t, "bob"), user(t, "carol")
	path := shareFile(t, alice, bob.public())
	if _, _, err := receiveFile(carol, path); err == nil {
		t.Error("a different user opened the package")
	}
	if _, err := os.Stat("received-report.txt"); err == nil {
		t.Error("a file was written for the wrong recipient")
	}
}

func TestReceiveRejectsDamagedPackages(t *testing.T) {
	workdir(t)
	alice, bob := user(t, "alice"), user(t, "bob")
	path := shareFile(t, alice, bob.public())

	var pkg Package
	if err := readJSON(path, &pkg); err != nil {
		t.Fatal(err)
	}
	pkg.Ciphertext[0] ^= 0xff
	writeJSON("tampered.share.json", pkg)
	if _, _, err := receiveFile(bob, "tampered.share.json"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("tampered ciphertext: %v", err)
	}

	write(t, "garbage.share.json", "not json")
	if _, _, err := receiveFile(bob, "garbage.share.json"); err == nil {
		t.Error("garbage package accepted")
	}
	if _, _, err := receiveFile(bob, "absent.share.json"); err == nil {
		t.Error("missing package accepted")
	}
}

func TestInteractiveSession(t *testing.T) {
	workdir(t)
	write(t, "todo.txt", "buy milk, call the bank, finish the lab")

	// Bob logs in once so that his public identity file exists
	script(t, "bob", "0")
	if _, err := os.Stat("bob.pub.json"); err != nil {
		t.Fatal("public identity was not written")
	}

	out := script(t, "alice",
		"2",                   // list: empty
		"1", "todo.txt", "pw", // add
		"2",                   // list
		"3", "todo.txt", "pw", // extract
		"4", "todo.txt", "pw", "bob.pub.json", // share
		"0")
	for _, want := range []string{
		"Logged in as alice", "The vault is empty", `Stored "todo.txt"`, "  todo.txt",
		"Saved extracted-todo.txt", "Package for bob saved as todo.txt.bob.share.json", "Recipient fingerprint:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	if got := mustRead(t, "extracted-todo.txt"); got != "buy milk, call the bank, finish the lab" {
		t.Errorf("extracted content = %q", got)
	}

	out = script(t, "bob", "5", "todo.txt.bob.share.json", "q")
	if !strings.Contains(out, "Signature valid, sent by alice") || !strings.Contains(out, "Saved received-todo.txt") {
		t.Errorf("receive output:\n%s", out)
	}
	if got := mustRead(t, "received-todo.txt"); got != "buy milk, call the bank, finish the lab" {
		t.Errorf("received content = %q", got)
	}
}

func TestInteractiveErrorsAreReportedNotFatal(t *testing.T) {
	workdir(t)
	out := script(t, "alice",
		"7", "abc", // unknown choices
		"1", "missing.txt", "pw", // add a missing file
		"1", "missing.txt", "", // empty password
		"3", "nothing", "pw", // extract an unknown entry
		"4", "nothing", "pw", "nobody.pub.json", // missing recipient file
		"5", "nothing.share.json", // missing package
		"0")
	for _, want := range []string{"Unknown choice", "password must not be empty", "no such vault entry", "error:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	if strings.Count(out, "Unknown choice") != 2 {
		t.Errorf("expected two 'Unknown choice' lines\n%s", out)
	}
}

func TestInteractiveRejectsBadRecipientName(t *testing.T) {
	workdir(t)
	write(t, "f.txt", "some content to share with somebody")
	write(t, "evil.pub.json", `{"Name":"../evil","RSAPublic":"","ECCPublic":""}`)
	out := script(t, "alice", "1", "f.txt", "pw", "4", "f.txt", "pw", "evil.pub.json", "0")
	if !strings.Contains(out, "invalid name") {
		t.Errorf("output:\n%s", out)
	}
	if matches, _ := filepath.Glob("*.share.json"); len(matches) != 0 {
		t.Errorf("package written: %v", matches)
	}
}

func TestInteractiveUsernameAndInputEnd(t *testing.T) {
	workdir(t)
	for _, name := range []string{"", "../evil", "a b", strings.Repeat("x", 33)} {
		if err := run(strings.NewReader(name+"\n"), &bytes.Buffer{}); err == nil {
			t.Errorf("username %q accepted", name)
		}
	}
	// Input that ends without choosing "quit" must end the program cleanly
	var out bytes.Buffer
	if err := run(strings.NewReader("alice\n"), &out); err != nil {
		t.Errorf("end of input after login: %v", err)
	}
	if err := run(strings.NewReader("alice\n1\nfile.txt\n"), &out); err != nil {
		t.Errorf("end of input mid-command: %v", err)
	}
}
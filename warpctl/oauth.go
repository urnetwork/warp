package main

// oauth signer key generation and rotation.
//
// The oauth authorization server signs access and id tokens with keys that are
// dedicated to it. They are deliberately NOT the domain tls keys used for
// ByJwt (vault jwt.yml): the ByJwt parser validates no registered claims, so a
// shared key would make a scoped oauth token verify as a full platform
// credential. Keeping the key sets disjoint makes that impossible rather than
// merely disallowed.
//
// The oauth runtime config (issuer, authorization endpoint, signer keys) lives
// in the env vault auth.yml beside the byjwt gates, not in services.yml:
// services.yml describes deployment topology, and auth.yml is the auth runtime
// config the server reads.
//
// Keys live in the shared vault alongside tls, under a dated version
// directory: <vault_home>/all/oauth/<Y.M.D>/<kid>.key. `oauth keygen` writes a
// new key to all/oauth.pending, and `oauth promote` moves it into all/oauth
// and lists it first in `oauth.signer_keys` of <vault_home>/<env>/auth.yml.
// The two steps are separated because every host must hold a key before any
// host signs with it: a host that has been told to sign with a key it does not
// have cannot serve, and a host that lacks a key another host is already
// signing with cannot verify those tokens. Deploy between keygen and promote.
//
// promote edits auth.yml by inserting lines rather than round-tripping the
// yaml, so comments and formatting survive.
//
// auth.yml references a key as `oauth/<kid>.key`; the vault resolver expands
// the version directory, so the reference does not name a version.
//
// The kid is the rfc 7638 jwk thumbprint, so it is derived from the key itself
// and cannot drift from it.
//
// §7.8 keeps the server's oauth keys in disjoint sets, named by a kid prefix:
// mcp (today's keys, no prefix), adm-, svc- and id-. `--set` names the set a
// keygen makes a key for and a promote lists; each set has at most one pending
// key, and the sets rotate independently. A prefixed set's public keys and the
// issuer go to <vault_home>/<env>/oauth-jwks-<set>.json at keygen and promote,
// so the blocks that only verify that set's tokens (evs and gkm for svc, §19.4)
// mount it and never a private key; deploy them before promoting, as for the
// signers.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/docopt/docopt-go"
	"gopkg.in/yaml.v3"
)

const oauthSignerAlg = "ES256"

// the `oauth` section of the env vault auth.yml, mirrored by server/oauth
type oauthAuthYml struct {
	Oauth *oauthAuthYmlOauth `yaml:"oauth"`
}

type oauthAuthYmlOauth struct {
	Issuer                string                   `yaml:"issuer"`
	AuthorizationEndpoint string                   `yaml:"authorization_endpoint"`
	SignerKeys            []*oauthAuthYmlSignerKey `yaml:"signer_keys"`
}

type oauthAuthYmlSignerKey struct {
	Kid        string `yaml:"kid"`
	Path       string `yaml:"path"`
	Alg        string `yaml:"alg"`
	CreateTime string `yaml:"create_time"`
}

// A set of §7.8's, as --set names it.
type oauthSignerKeySet string

const (
	oauthSignerKeySetMcp     oauthSignerKeySet = "mcp"
	oauthSignerKeySetAdmin   oauthSignerKeySet = "adm"
	oauthSignerKeySetService oauthSignerKeySet = "svc"
	oauthSignerKeySetId      oauthSignerKeySet = "id"
)

// The sets with a kid prefix.
var prefixedOauthSignerKeySets = []oauthSignerKeySet{oauthSignerKeySetAdmin, oauthSignerKeySetService, oauthSignerKeySetId}

// The set --set names, mcp when it names none.
func parseOauthSignerKeySet(set string) (oauthSignerKeySet, error) {
	switch oauthSignerKeySet(set) {
	case "", oauthSignerKeySetMcp:
		return oauthSignerKeySetMcp, nil
	case oauthSignerKeySetAdmin, oauthSignerKeySetService, oauthSignerKeySetId:
		return oauthSignerKeySet(set), nil
	default:
		return "", fmt.Errorf("--set=%s is no oauth signer key set; one of mcp, adm, svc, id", set)
	}
}

// The prefix of the set's kids, "" for mcp, as server/oauth's SignerKeySet.
func (self oauthSignerKeySet) kidPrefix() string {
	if self == oauthSignerKeySetMcp {
		return ""
	}
	return string(self) + "-"
}

// The set a kid names.
func oauthSignerKeySetOfKid(kid string) oauthSignerKeySet {
	for _, set := range prefixedOauthSignerKeySets {
		if strings.HasPrefix(kid, set.kidPrefix()) {
			return set
		}
	}
	return oauthSignerKeySetMcp
}

// The env's public jwks file of a prefixed set, which that set's verifiers
// mount.
func oauthPublicJwksPath(vaultHome string, env string, set oauthSignerKeySet) string {
	return filepath.Join(vaultHome, env, fmt.Sprintf("oauth-jwks-%s.json", set))
}

func oauthKeygen(opts docopt.Opts) {
	warpState := getWarpState()
	env, _ := opts.String("<env>")
	setName, _ := opts.String("--set")
	vaultHome := warpState.warpSettings.RequireVaultHome()
	set, err := parseOauthSignerKeySet(setName)
	if err != nil {
		panic(err)
	}

	keyPath, err := oauthKeygenSetAt(vaultHome, env, set)
	if err != nil {
		panic(err)
	}

	Out.Printf("Wrote %s\n", keyPath)
	Out.Printf("\n")
	Out.Printf("**important**: every host must have this key **before** any host signs\n")
	Out.Printf("with it. A host that is told to sign with a key it does not have cannot\n")
	Out.Printf("serve, and a host missing a key another host signs with cannot verify\n")
	Out.Printf("those tokens.\n")
	Out.Printf("\n")
	if set != oauthSignerKeySetMcp {
		Out.Printf("Wrote %s with the pending key, for the blocks that verify %s tokens.\n", oauthPublicJwksPath(vaultHome, env, set), set)
		Out.Printf("\n")
	}
	Out.Printf("Rollout:\n")
	Out.Printf("  1. deploy (xops edges) so every host has the pending key\n")
	Out.Printf("  2. run `warpctl oauth promote %s --set=%s`, which moves the key into all/oauth\n", env, set)
	Out.Printf("     and lists it first in `oauth.signer_keys` of %s\n", filepath.Join(vaultHome, env, "auth.yml"))
	Out.Printf("  3. deploy again so hosts begin signing with it\n")
	Out.Printf("  4. once every token signed by the previous key has expired, remove that\n")
	Out.Printf("     key's block from auth.yml (access tokens live an hour)\n")
	Out.Printf("\n")
	Out.Printf("**important**: this key must never be added to jwt.yml tls_key_paths.\n")
}

// Generates an mcp signer key into all/oauth.pending (oauthKeygenSetAt).
func oauthKeygenAt(vaultHome string, env string) (string, error) {
	return oauthKeygenSetAt(vaultHome, env, oauthSignerKeySetMcp)
}

// The pending keys of the set, under all/oauth.pending.
func pendingOauthSignerKeyPaths(vaultHome string, set oauthSignerKeySet) ([]string, error) {
	pendingKeyPaths, err := filepath.Glob(filepath.Join(vaultHome, "all", "oauth.pending", "*", "*.key"))
	if err != nil {
		return nil, err
	}
	setKeyPaths := []string{}
	for _, pendingKeyPath := range pendingKeyPaths {
		if oauthSignerKeySetOfKid(strings.TrimSuffix(filepath.Base(pendingKeyPath), ".key")) == set {
			setKeyPaths = append(setKeyPaths, pendingKeyPath)
		}
	}
	return setKeyPaths, nil
}

// Generates a signer key of the set into all/oauth.pending, its kid the set's
// prefix and its thumbprint. The env's auth.yml is checked first, so a rotation
// that `oauth promote` could not finish is rejected before anything is
// written. For a prefixed set, the env's public jwks of the set is rewritten
// with the pending key in it.
func oauthKeygenSetAt(vaultHome string, env string, set oauthSignerKeySet) (string, error) {
	authYmlPath := filepath.Join(vaultHome, env, "auth.yml")
	authYml, err := os.ReadFile(authYmlPath)
	if err != nil {
		return "", fmt.Errorf("%w; %s", err, oauthConfigGuidance())
	}

	pendingHome := filepath.Join(vaultHome, "all", "oauth.pending")
	if pendingKeyPaths, err := pendingOauthSignerKeyPaths(vaultHome, set); err == nil && 0 < len(pendingKeyPaths) {
		return "", fmt.Errorf(
			"%s is already pending; `warpctl oauth promote %s --set=%s` it or remove it first",
			pendingKeyPaths[0],
			env,
			set,
		)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	thumbprint, err := oauthSignerKid(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}
	kid := set.kidPrefix() + thumbprint

	// prove the promote-time edit will land before writing the key
	if _, err := insertOauthSignerKey(authYml, kid, time.Now()); err != nil {
		return "", fmt.Errorf("%s: %w", authYmlPath, err)
	}

	year, month, day := time.Now().Date()
	oauthHome := filepath.Join(pendingHome, fmt.Sprintf("%d.%d.%d", year, month, day))
	if err := os.MkdirAll(oauthHome, 0700); err != nil {
		return "", err
	}

	keyPath := filepath.Join(oauthHome, fmt.Sprintf("%s.key", kid))

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		return "", fmt.Errorf("write %s: %w", keyPath, err)
	}

	if set != oauthSignerKeySetMcp {
		if err := writeOauthPublicJwks(vaultHome, env, set); err != nil {
			return "", fmt.Errorf("the key is pending at %s, but its set's jwks was not written: %w", keyPath, err)
		}
	}

	return keyPath, nil
}

// One public key of the env's jwks file, as server/oauth's Jwk.
type oauthPublicJwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// The env's jwks file of a set, as server/oauth's PublicJwksDocument: the
// issuer and the set's public keys.
type oauthPublicJwksDocument struct {
	Issuer string            `json:"issuer"`
	Keys   []*oauthPublicJwk `json:"keys"`
}

// Writes the env's public jwks of a prefixed set: the set's pending key, if any,
// then the keys auth.yml lists for the set, newest first, each read from its
// file in all/oauth and named by its own thumbprint, and the issuer. A listed
// key whose file is missing fails the write, since the jwks would not verify
// the tokens it signs.
func writeOauthPublicJwks(vaultHome string, env string, set oauthSignerKeySet) error {
	authYml, err := os.ReadFile(filepath.Join(vaultHome, env, "auth.yml"))
	if err != nil {
		return err
	}
	var config oauthAuthYml
	if err := yaml.Unmarshal(authYml, &config); err != nil {
		return err
	}
	if config.Oauth == nil || config.Oauth.Issuer == "" {
		return fmt.Errorf("auth.yml names no oauth issuer; %s", oauthConfigGuidance())
	}

	keyPaths, err := pendingOauthSignerKeyPaths(vaultHome, set)
	if err != nil {
		return err
	}
	for _, signerKey := range config.Oauth.SignerKeys {
		if oauthSignerKeySetOfKid(signerKey.Kid) != set {
			continue
		}
		listedKeyPaths, err := filepath.Glob(filepath.Join(vaultHome, "all", "oauth", "*", signerKey.Kid+".key"))
		if err != nil {
			return err
		}
		if len(listedKeyPaths) != 1 {
			return fmt.Errorf("auth.yml lists %s, and all/oauth holds %d files for it", signerKey.Kid, len(listedKeyPaths))
		}
		keyPaths = append(keyPaths, listedKeyPaths[0])
	}

	document := &oauthPublicJwksDocument{Issuer: config.Oauth.Issuer, Keys: []*oauthPublicJwk{}}
	for _, keyPath := range keyPaths {
		keyPem, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		privateKey, err := parseOauthSignerKeyPem(keyPem)
		if err != nil {
			return fmt.Errorf("%s: %w", keyPath, err)
		}
		thumbprint, err := oauthSignerKid(&privateKey.PublicKey)
		if err != nil {
			return err
		}
		kid := set.kidPrefix() + thumbprint
		if filepath.Base(keyPath) != kid+".key" {
			return fmt.Errorf("%s does not match its key, which is %s", keyPath, kid)
		}
		x, y := oauthPublicCoordinates(&privateKey.PublicKey)
		document.Keys = append(document.Keys, &oauthPublicJwk{
			Kty: "EC",
			Crv: "P-256",
			Kid: kid,
			Alg: oauthSignerAlg,
			Use: "sig",
			X:   x,
			Y:   y,
		})
	}

	documentJson, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	jwksPath := oauthPublicJwksPath(vaultHome, env, set)
	tempPath := jwksPath + ".oauth-jwks"
	if err := os.WriteFile(tempPath, append(documentJson, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tempPath, jwksPath)
}

// Fixed width base64url coordinates, as jwk requires.
func oauthPublicCoordinates(publicKey *ecdsa.PublicKey) (string, string) {
	byteLen := (publicKey.Curve.Params().BitSize + 7) / 8
	pad := func(i *big.Int) string {
		b := i.Bytes()
		if len(b) < byteLen {
			padded := make([]byte, byteLen)
			copy(padded[byteLen-len(b):], b)
			b = padded
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return pad(publicKey.X), pad(publicKey.Y)
}

func oauthPromote(opts docopt.Opts) {
	warpState := getWarpState()
	env, _ := opts.String("<env>")
	setName, _ := opts.String("--set")
	vaultHome := warpState.warpSettings.RequireVaultHome()
	set, err := parseOauthSignerKeySet(setName)
	if err != nil {
		panic(err)
	}

	promotion, err := oauthPromoteSetAt(vaultHome, env, set)
	if err != nil {
		panic(err)
	}

	Out.Printf("Moved %s\n", promotion.fromPath)
	Out.Printf("   -> %s\n", promotion.toPath)
	Out.Printf("Listed kid %s first in `oauth.signer_keys` of %s\n", promotion.kid, promotion.authYmlPath)
	Out.Printf("\n")
	Out.Printf("Deploy (xops edges) so hosts begin signing with it. Once every token\n")
	Out.Printf("signed by the previous key has expired (access tokens live an hour),\n")
	Out.Printf("remove that key's block from auth.yml.\n")
}

type oauthPromotion struct {
	kid         string
	fromPath    string
	toPath      string
	authYmlPath string
}

// Promotes the pending mcp signer key (oauthPromoteSetAt).
func oauthPromoteAt(vaultHome string, env string) (*oauthPromotion, error) {
	return oauthPromoteSetAt(vaultHome, env, oauthSignerKeySetMcp)
}

// Moves the set's single pending signer key from all/oauth.pending into
// all/oauth and lists it first in `oauth.signer_keys` of the env's auth.yml.
// Everything is validated before the first write, so a failure leaves the vault
// as it was. For a prefixed set, the env's public jwks of the set is rewritten
// from what auth.yml then lists.
func oauthPromoteSetAt(vaultHome string, env string, set oauthSignerKeySet) (*oauthPromotion, error) {
	authYmlPath := filepath.Join(vaultHome, env, "auth.yml")
	authYml, err := os.ReadFile(authYmlPath)
	if err != nil {
		return nil, fmt.Errorf("%w; %s", err, oauthConfigGuidance())
	}
	authYmlInfo, err := os.Stat(authYmlPath)
	if err != nil {
		return nil, err
	}

	pendingHome := filepath.Join(vaultHome, "all", "oauth.pending")
	pendingKeyPaths, err := pendingOauthSignerKeyPaths(vaultHome, set)
	if err != nil {
		return nil, err
	}
	if len(pendingKeyPaths) == 0 {
		return nil, fmt.Errorf("no pending signer key of the %s set under %s; run `warpctl oauth keygen %s --set=%s` first", set, pendingHome, env, set)
	}
	if 1 < len(pendingKeyPaths) {
		return nil, fmt.Errorf(
			"multiple pending signer keys of the %s set (%s); promote expects exactly one, remove the strays and rerun",
			set,
			strings.Join(pendingKeyPaths, ", "),
		)
	}
	fromPath := pendingKeyPaths[0]

	keyPem, err := os.ReadFile(fromPath)
	if err != nil {
		return nil, err
	}
	privateKey, err := parseOauthSignerKeyPem(keyPem)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fromPath, err)
	}
	thumbprint, err := oauthSignerKid(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fromPath, err)
	}
	kid := set.kidPrefix() + thumbprint
	if keyName := fmt.Sprintf("%s.key", kid); filepath.Base(fromPath) != keyName {
		return nil, fmt.Errorf("%s does not match its key, which is %s", fromPath, kid)
	}

	keyInfo, err := os.Stat(fromPath)
	if err != nil {
		return nil, err
	}
	// the mtime is when keygen wrote the key
	editedAuthYml, err := insertOauthSignerKey(authYml, kid, keyInfo.ModTime())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", authYmlPath, err)
	}

	toDir := filepath.Join(vaultHome, "all", "oauth", filepath.Base(filepath.Dir(fromPath)))
	toPath := filepath.Join(toDir, filepath.Base(fromPath))
	if _, err := os.Stat(toPath); err == nil {
		return nil, fmt.Errorf("%s already exists", toPath)
	}
	if err := os.MkdirAll(toDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Rename(fromPath, toPath); err != nil {
		return nil, err
	}
	// tidy now-empty pending dirs; Remove refuses non-empty ones, which is the
	// correct ignore
	os.Remove(filepath.Dir(fromPath))
	os.Remove(pendingHome)

	// write through a temp file so a failure cannot leave a half written
	// auth.yml
	tempPath := authYmlPath + ".oauth-promote"
	if err := os.WriteFile(tempPath, editedAuthYml, authYmlInfo.Mode().Perm()); err != nil {
		return nil, fmt.Errorf("write %s (the key was already moved to %s): %w", authYmlPath, toPath, err)
	}
	if err := os.Rename(tempPath, authYmlPath); err != nil {
		return nil, fmt.Errorf("write %s (the key was already moved to %s): %w", authYmlPath, toPath, err)
	}

	if set != oauthSignerKeySetMcp {
		if err := writeOauthPublicJwks(vaultHome, env, set); err != nil {
			return nil, fmt.Errorf("the key was promoted, but its set's jwks was not rewritten: %w", err)
		}
	}

	return &oauthPromotion{
		kid:         kid,
		fromPath:    fromPath,
		toPath:      toPath,
		authYmlPath: authYmlPath,
	}, nil
}

// The issuer and authorization endpoint are operator decisions warpctl cannot
// invent, so the oauth section is seeded by hand once per env.
func oauthConfigGuidance() string {
	return "add the oauth section to the env vault auth.yml first:\n" +
		"\n" +
		"    oauth:\n" +
		"        issuer: https://auth.<domain>\n" +
		"        authorization_endpoint: https://<consent-origin>/authorize\n" +
		"        signer_keys:\n"
}

var oauthLineRe = regexp.MustCompile(`^oauth:\s*(?:#.*)?$`)
var oauthSignerKeysLineRe = regexp.MustCompile(`^(\s+)signer_keys:\s*(?:#.*)?$`)
var oauthSignerKeyItemRe = regexp.MustCompile(`^(\s*)- `)

// insertOauthSignerKey returns authYml with a signer key block for kid
// inserted at the top of `oauth.signer_keys`, leaving every other line
// untouched so comments and formatting survive. The result is re-parsed to
// prove the edit landed as intended before it is returned.
func insertOauthSignerKey(authYml []byte, kid string, createTime time.Time) ([]byte, error) {
	var before oauthAuthYml
	if err := yaml.Unmarshal(authYml, &before); err != nil {
		return nil, err
	}
	if before.Oauth == nil {
		return nil, fmt.Errorf("no oauth section; %s", oauthConfigGuidance())
	}
	if before.Oauth.Issuer == "" {
		return nil, fmt.Errorf("oauth.issuer is required; %s", oauthConfigGuidance())
	}
	if before.Oauth.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("oauth.authorization_endpoint is required; %s", oauthConfigGuidance())
	}
	for _, signerKey := range before.Oauth.SignerKeys {
		if signerKey.Kid == kid {
			return nil, fmt.Errorf("kid %s is already listed", kid)
		}
	}

	lines := strings.Split(string(authYml), "\n")

	oauthIndex := -1
	for i, line := range lines {
		if oauthLineRe.MatchString(line) {
			oauthIndex = i
			break
		}
	}
	if oauthIndex < 0 {
		// the parse found an oauth section but no literal top-level `oauth:`
		// line exists: an anchor or flow style this editor does not handle
		return nil, fmt.Errorf("no top-level `oauth:` line to edit")
	}

	// find `signer_keys:` within the oauth block. Comments end no block: yaml
	// comments are indentation insensitive.
	signerKeysIndex := -1
	signerKeysIndent := ""
	for i := oauthIndex + 1; i < len(lines); i += 1 {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// the next top-level key ends the oauth block
			break
		}
		if m := oauthSignerKeysLineRe.FindStringSubmatch(line); m != nil {
			signerKeysIndex = i
			signerKeysIndent = m[1]
			break
		}
	}
	if signerKeysIndex < 0 {
		return nil, fmt.Errorf("the oauth section has no signer_keys; %s", oauthConfigGuidance())
	}

	// insert above the first existing item, matching its indent; with no items
	// yet, insert directly under `signer_keys:` one indent level deeper
	insertIndex := signerKeysIndex + 1
	itemIndent := signerKeysIndent + signerKeysIndent
	for i := signerKeysIndex + 1; i < len(lines); i += 1 {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// a block sequence may sit at the same indent as its key or deeper
		if m := oauthSignerKeyItemRe.FindStringSubmatch(line); m != nil && len(signerKeysIndent) <= len(m[1]) {
			insertIndex = i
			itemIndent = m[1]
		}
		break
	}

	block := []string{
		fmt.Sprintf("%s- kid: %s", itemIndent, kid),
		fmt.Sprintf("%s  path: oauth/%s.key", itemIndent, kid),
		fmt.Sprintf("%s  alg: %s", itemIndent, oauthSignerAlg),
		fmt.Sprintf("%s  create_time: %s", itemIndent, createTime.UTC().Format(time.RFC3339)),
	}
	editedLines := slices.Concat(lines[:insertIndex], block, lines[insertIndex:])
	editedAuthYml := []byte(strings.Join(editedLines, "\n"))

	var after oauthAuthYml
	if err := yaml.Unmarshal(editedAuthYml, &after); err != nil {
		return nil, fmt.Errorf("the edit produced invalid yaml: %w", err)
	}
	if after.Oauth == nil || len(after.Oauth.SignerKeys) != len(before.Oauth.SignerKeys)+1 {
		return nil, fmt.Errorf("the edit did not add a signer key")
	}
	first := after.Oauth.SignerKeys[0]
	if first.Kid != kid || first.Path != fmt.Sprintf("oauth/%s.key", kid) || first.Alg != oauthSignerAlg {
		return nil, fmt.Errorf("the edit did not list the new key first")
	}
	for i, signerKey := range before.Oauth.SignerKeys {
		if after.Oauth.SignerKeys[i+1].Kid != signerKey.Kid {
			return nil, fmt.Errorf("the edit reordered the existing keys")
		}
	}

	return editedAuthYml, nil
}

// keygen writes pkcs8; the ec form is accepted for keys that predate it
func parseOauthSignerKeyPem(keyPem []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, fmt.Errorf("not pem")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an ec key")
		}
		return ecKey, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("could not parse the key")
}

// The rfc 7638 jwk thumbprint of an ec public key: base64url(sha256) over the
// canonical json with lexicographically ordered members and no whitespace.
func oauthSignerKid(publicKey *ecdsa.PublicKey) (string, error) {
	curve := publicKey.Curve.Params()

	byteLen := (curve.BitSize + 7) / 8
	pad := func(i *big.Int) string {
		b := i.Bytes()
		if len(b) < byteLen {
			padded := make([]byte, byteLen)
			copy(padded[byteLen-len(b):], b)
			b = padded
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}

	var crv string
	switch curve.Name {
	case "P-256":
		crv = "P-256"
	default:
		return "", fmt.Errorf("unsupported curve %s", curve.Name)
	}

	// the member order here is normative, not stylistic
	canonical := fmt.Sprintf(
		`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
		crv,
		pad(publicKey.X),
		pad(publicKey.Y),
	)

	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

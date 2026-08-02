package main

// oauth signer key generation.
//
// The oauth authorization server signs access and id tokens with keys that are
// dedicated to it. They are deliberately NOT the domain tls keys used for
// ByJwt (vault jwt.yml): the ByJwt parser validates no registered claims, so a
// shared key would make a scoped oauth token verify as a full platform
// credential. Keeping the key sets disjoint makes that impossible rather than
// merely disallowed.
//
// Keys live in the shared vault alongside tls, under a dated version
// directory: <vault_home>/all/oauth/<Y.M.D>/<kid>.key. New keys are written to
// all/oauth.pending first and are promoted to all/oauth only once every host
// has them, exactly like tls.pending. The ordering matters more here than for
// certs: a host that has been told to sign with a key it does not have cannot
// serve, and a host that lacks a key another host is already signing with
// cannot verify those tokens.
//
// services.yml references a key as `oauth/<kid>.key`; the vault resolver
// expands the version directory, so the reference does not name a version.
//
// The kid is the rfc 7638 jwk thumbprint, so it is derived from the key itself
// and cannot drift from it.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/docopt/docopt-go"
)

const oauthSignerAlg = "ES256"

// Generates a signer key and prints the services.yml block that references it.
// The file is written but services.yml is not edited, so the operator reviews
// the rotation before it takes effect -- and because rewriting the yaml would
// drop its comments.
func oauthKeygen(opts docopt.Opts) {
	warpState := getWarpState()

	env, _ := opts.String("<env>")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	kid, err := oauthSignerKid(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	year, month, day := time.Now().Date()
	oauthHome := filepath.Join(
		warpState.warpSettings.RequireVaultHome(),
		"all",
		"oauth.pending",
		fmt.Sprintf("%d.%d.%d", year, month, day),
	)
	if err := os.MkdirAll(oauthHome, 0700); err != nil {
		panic(err)
	}

	keyName := fmt.Sprintf("%s.key", kid)
	keyPath := filepath.Join(oauthHome, keyName)

	if _, err := os.Stat(keyPath); err == nil {
		panic(fmt.Errorf("%s already exists; a kid is derived from the key, so this would be the same key", keyPath))
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		panic(fmt.Errorf("write %s: %w", keyPath, err))
	}

	Out.Printf("Wrote %s\n", keyPath)
	Out.Printf("\n")
	Out.Printf("**important**: deploy this to every host **before** moving it from\n")
	Out.Printf("all/oauth.pending to all/oauth and listing it first in services.yml.\n")
	Out.Printf("A host that is told to sign with a key it does not have cannot serve,\n")
	Out.Printf("and a host missing a key another host signs with cannot verify those tokens.\n")
	Out.Printf("\n")
	Out.Printf("Rollout:\n")
	Out.Printf("  1. deploy (xops edges) so every host has the pending key\n")
	Out.Printf("  2. move all/oauth.pending/... into all/oauth/...\n")
	Out.Printf("  3. add the block below to the TOP of `oauth.signer_keys` in %s/%s/services.yml\n",
		warpState.warpSettings.RequireVaultHome(), env)
	Out.Printf("  4. keep the previous key listed until every token it signed has expired,\n")
	Out.Printf("     so the jwks can still verify them\n")
	Out.Printf("\n")
	Out.Printf("        - kid: %s\n", kid)
	Out.Printf("          path: oauth/%s\n", keyName)
	Out.Printf("          alg: %s\n", oauthSignerAlg)
	Out.Printf("          create_time: %s\n", time.Now().UTC().Format(time.RFC3339))
	Out.Printf("\n")
	Out.Printf("**important**: this key must never be added to jwt.yml tls_key_paths.\n")
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

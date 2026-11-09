package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"gopkg.in/yaml.v3"
)

const testOauthAuthYml = `# test auth config
reject_expired: false

# oauth authorization server
oauth:
    issuer: https://auth.example.com
    # the consent page origin
    authorization_endpoint: https://app.example.com/authorize
    signer_keys:
        - kid: OLDKID
          path: oauth/OLDKID.key
          alg: ES256
          create_time: 2026-07-31T00:00:00Z

reject_missing_expiration: false
`

func TestInsertOauthSignerKey(t *testing.T) {
	createTime := time.Date(2026, 8, 10, 12, 30, 0, 0, time.UTC)

	edited, err := insertOauthSignerKey([]byte(testOauthAuthYml), "NEWKID", createTime)
	assert.Equal(t, err, nil)

	expected := `# test auth config
reject_expired: false

# oauth authorization server
oauth:
    issuer: https://auth.example.com
    # the consent page origin
    authorization_endpoint: https://app.example.com/authorize
    signer_keys:
        - kid: NEWKID
          path: oauth/NEWKID.key
          alg: ES256
          create_time: 2026-08-10T12:30:00Z
        - kid: OLDKID
          path: oauth/OLDKID.key
          alg: ES256
          create_time: 2026-07-31T00:00:00Z

reject_missing_expiration: false
`
	assert.Equal(t, string(edited), expected)
}

func TestInsertOauthSignerKeyEmptyList(t *testing.T) {
	authYml := `oauth:
    issuer: https://auth.example.com
    authorization_endpoint: https://app.example.com/authorize
    signer_keys:

reject_expired: false
`
	createTime := time.Date(2026, 8, 10, 12, 30, 0, 0, time.UTC)

	edited, err := insertOauthSignerKey([]byte(authYml), "NEWKID", createTime)
	assert.Equal(t, err, nil)

	expected := `oauth:
    issuer: https://auth.example.com
    authorization_endpoint: https://app.example.com/authorize
    signer_keys:
        - kid: NEWKID
          path: oauth/NEWKID.key
          alg: ES256
          create_time: 2026-08-10T12:30:00Z

reject_expired: false
`
	assert.Equal(t, string(edited), expected)
}

func TestInsertOauthSignerKeyCommentAboveFirstItem(t *testing.T) {
	authYml := `oauth:
    issuer: https://auth.example.com
    authorization_endpoint: https://app.example.com/authorize
    signer_keys:
        # newest first
        - kid: OLDKID
          path: oauth/OLDKID.key
          alg: ES256
`
	createTime := time.Date(2026, 8, 10, 12, 30, 0, 0, time.UTC)

	edited, err := insertOauthSignerKey([]byte(authYml), "NEWKID", createTime)
	assert.Equal(t, err, nil)

	expected := `oauth:
    issuer: https://auth.example.com
    authorization_endpoint: https://app.example.com/authorize
    signer_keys:
        # newest first
        - kid: NEWKID
          path: oauth/NEWKID.key
          alg: ES256
          create_time: 2026-08-10T12:30:00Z
        - kid: OLDKID
          path: oauth/OLDKID.key
          alg: ES256
`
	assert.Equal(t, string(edited), expected)
}

func TestInsertOauthSignerKeyErrors(t *testing.T) {
	createTime := time.Date(2026, 8, 10, 12, 30, 0, 0, time.UTC)

	_, err := insertOauthSignerKey([]byte("reject_expired: false\n"), "NEWKID", createTime)
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "no oauth section"), true)

	noIssuer := `oauth:
    authorization_endpoint: https://app.example.com/authorize
    signer_keys:
`
	_, err = insertOauthSignerKey([]byte(noIssuer), "NEWKID", createTime)
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "oauth.issuer"), true)

	noEndpoint := `oauth:
    issuer: https://auth.example.com
    signer_keys:
`
	_, err = insertOauthSignerKey([]byte(noEndpoint), "NEWKID", createTime)
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "oauth.authorization_endpoint"), true)

	noSignerKeys := `oauth:
    issuer: https://auth.example.com
    authorization_endpoint: https://app.example.com/authorize
`
	_, err = insertOauthSignerKey([]byte(noSignerKeys), "NEWKID", createTime)
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "no signer_keys"), true)

	_, err = insertOauthSignerKey([]byte(testOauthAuthYml), "OLDKID", createTime)
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "already listed"), true)

	// flow style is valid yaml but not editable line-wise
	flow := `oauth: {issuer: https://auth.example.com, authorization_endpoint: https://app.example.com/authorize, signer_keys: []}
`
	_, err = insertOauthSignerKey([]byte(flow), "NEWKID", createTime)
	assert.Equal(t, err != nil, true)
}

func TestOauthKeygenPromote(t *testing.T) {
	vaultHome := t.TempDir()
	authYmlPath := filepath.Join(vaultHome, "test", "auth.yml")
	err := os.MkdirAll(filepath.Dir(authYmlPath), 0700)
	assert.Equal(t, err, nil)
	err = os.WriteFile(authYmlPath, []byte(testOauthAuthYml), 0600)
	assert.Equal(t, err, nil)

	keyPath, err := oauthKeygenAt(vaultHome, "test")
	assert.Equal(t, err, nil)
	pendingHome := filepath.Join(vaultHome, "all", "oauth.pending")
	assert.Equal(t, strings.HasPrefix(keyPath, pendingHome+string(os.PathSeparator)), true)
	_, err = os.Stat(keyPath)
	assert.Equal(t, err, nil)

	// keygen does not edit auth.yml
	authYml, err := os.ReadFile(authYmlPath)
	assert.Equal(t, err, nil)
	assert.Equal(t, string(authYml), testOauthAuthYml)

	// a second keygen refuses while a key is pending
	_, err = oauthKeygenAt(vaultHome, "test")
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "already pending"), true)

	kid := strings.TrimSuffix(filepath.Base(keyPath), ".key")
	keyInfo, err := os.Stat(keyPath)
	assert.Equal(t, err, nil)

	promotion, err := oauthPromoteAt(vaultHome, "test")
	assert.Equal(t, err, nil)
	assert.Equal(t, promotion.kid, kid)
	assert.Equal(t, promotion.fromPath, keyPath)
	assert.Equal(t, promotion.authYmlPath, authYmlPath)

	// the key moved into all/oauth under the same dated version directory
	expectedToPath := filepath.Join(
		vaultHome, "all", "oauth",
		filepath.Base(filepath.Dir(keyPath)),
		filepath.Base(keyPath),
	)
	assert.Equal(t, promotion.toPath, expectedToPath)
	_, err = os.Stat(expectedToPath)
	assert.Equal(t, err, nil)
	_, err = os.Stat(pendingHome)
	assert.Equal(t, err != nil, true)

	// auth.yml lists the new key first, the old key second, comments intact
	editedAuthYml, err := os.ReadFile(authYmlPath)
	assert.Equal(t, err, nil)
	var edited oauthAuthYml
	err = yaml.Unmarshal(editedAuthYml, &edited)
	assert.Equal(t, err, nil)
	assert.Equal(t, len(edited.Oauth.SignerKeys), 2)
	assert.Equal(t, edited.Oauth.SignerKeys[0].Kid, kid)
	assert.Equal(t, edited.Oauth.SignerKeys[0].Path, "oauth/"+kid+".key")
	assert.Equal(t, edited.Oauth.SignerKeys[0].Alg, "ES256")
	assert.Equal(t, edited.Oauth.SignerKeys[0].CreateTime, keyInfo.ModTime().UTC().Format(time.RFC3339))
	assert.Equal(t, edited.Oauth.SignerKeys[1].Kid, "OLDKID")
	assert.Equal(t, strings.Contains(string(editedAuthYml), "# the consent page origin"), true)
	assert.Equal(t, strings.HasPrefix(string(editedAuthYml), "# test auth config"), true)

	// nothing left to promote
	_, err = oauthPromoteAt(vaultHome, "test")
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "no pending signer key"), true)
}

func TestOauthKeygenRequiresOauthSection(t *testing.T) {
	vaultHome := t.TempDir()
	authYmlPath := filepath.Join(vaultHome, "test", "auth.yml")
	err := os.MkdirAll(filepath.Dir(authYmlPath), 0700)
	assert.Equal(t, err, nil)
	err = os.WriteFile(authYmlPath, []byte("reject_expired: false\n"), 0600)
	assert.Equal(t, err, nil)

	_, err = oauthKeygenAt(vaultHome, "test")
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "no oauth section"), true)

	// the doomed rotation wrote no key
	pendingKeyPaths, err := filepath.Glob(filepath.Join(vaultHome, "all", "oauth.pending", "*", "*.key"))
	assert.Equal(t, err, nil)
	assert.Equal(t, len(pendingKeyPaths), 0)
}

func TestOauthKeygenRequiresAuthYml(t *testing.T) {
	vaultHome := t.TempDir()

	_, err := oauthKeygenAt(vaultHome, "test")
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "auth.yml"), true)
}

// §7.8's sets rotate independently: an svc key's kid carries its prefix, one
// pending key per set, and promote lists only the set it names. Each keygen and
// promote of a prefixed set writes the env's public jwks of that set, the issuer
// and the set's keys only, which its verifiers mount.
func TestOauthKeygenPromoteBySet(t *testing.T) {
	vaultHome := t.TempDir()
	authYmlPath := filepath.Join(vaultHome, "test", "auth.yml")
	err := os.MkdirAll(filepath.Dir(authYmlPath), 0700)
	assert.Equal(t, err, nil)
	err = os.WriteFile(authYmlPath, []byte(testOauthAuthYml), 0600)
	assert.Equal(t, err, nil)
	jwksPath := oauthPublicJwksPath(vaultHome, "test", oauthSignerKeySetService)

	readJwks := func() *oauthPublicJwksDocument {
		t.Helper()
		data, err := os.ReadFile(jwksPath)
		assert.Equal(t, err, nil)
		document := &oauthPublicJwksDocument{}
		assert.Equal(t, json.Unmarshal(data, document), nil)
		return document
	}

	serviceKeyPath, err := oauthKeygenSetAt(vaultHome, "test", oauthSignerKeySetService)
	assert.Equal(t, err, nil)
	serviceKid := strings.TrimSuffix(filepath.Base(serviceKeyPath), ".key")
	assert.Equal(t, strings.HasPrefix(serviceKid, "svc-"), true)
	assert.Equal(t, oauthSignerKeySetOfKid(serviceKid), oauthSignerKeySetService)

	// the pending key is already in the set's jwks, so verifiers can be deployed
	// before the issuer signs with it; the mcp key is not in it
	document := readJwks()
	assert.Equal(t, document.Issuer, "https://auth.example.com")
	assert.Equal(t, len(document.Keys), 1)
	assert.Equal(t, document.Keys[0].Kid, serviceKid)
	assert.Equal(t, document.Keys[0].Kty, "EC")
	assert.Equal(t, document.Keys[0].Crv, "P-256")
	assert.Equal(t, document.Keys[0].Alg, "ES256")
	assert.Equal(t, len(document.Keys[0].X), 43)
	assert.Equal(t, len(document.Keys[0].Y), 43)

	// one pending key per set: a second svc key refuses, an mcp key does not
	_, err = oauthKeygenSetAt(vaultHome, "test", oauthSignerKeySetService)
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "already pending"), true)
	mcpKeyPath, err := oauthKeygenAt(vaultHome, "test")
	assert.Equal(t, err, nil)
	mcpKid := strings.TrimSuffix(filepath.Base(mcpKeyPath), ".key")
	assert.Equal(t, oauthSignerKeySetOfKid(mcpKid), oauthSignerKeySetMcp)

	// another set has nothing to promote
	_, err = oauthPromoteSetAt(vaultHome, "test", oauthSignerKeySetAdmin)
	assert.Equal(t, err != nil, true)
	assert.Equal(t, strings.Contains(err.Error(), "no pending signer key of the adm set"), true)

	promotion, err := oauthPromoteSetAt(vaultHome, "test", oauthSignerKeySetService)
	assert.Equal(t, err, nil)
	assert.Equal(t, promotion.kid, serviceKid)
	editedAuthYml, err := os.ReadFile(authYmlPath)
	assert.Equal(t, err, nil)
	var edited oauthAuthYml
	assert.Equal(t, yaml.Unmarshal(editedAuthYml, &edited), nil)
	assert.Equal(t, len(edited.Oauth.SignerKeys), 2)
	assert.Equal(t, edited.Oauth.SignerKeys[0].Kid, serviceKid)
	assert.Equal(t, edited.Oauth.SignerKeys[0].Path, "oauth/"+serviceKid+".key")
	// the mcp key is still pending, untouched
	_, err = os.Stat(mcpKeyPath)
	assert.Equal(t, err, nil)

	// the jwks now comes from what auth.yml lists
	document = readJwks()
	assert.Equal(t, len(document.Keys), 1)
	assert.Equal(t, document.Keys[0].Kid, serviceKid)

	// a rotation keeps the previous svc key verifying: both are in the jwks,
	// the newest first
	nextKeyPath, err := oauthKeygenSetAt(vaultHome, "test", oauthSignerKeySetService)
	assert.Equal(t, err, nil)
	nextKid := strings.TrimSuffix(filepath.Base(nextKeyPath), ".key")
	_, err = oauthPromoteSetAt(vaultHome, "test", oauthSignerKeySetService)
	assert.Equal(t, err, nil)
	document = readJwks()
	assert.Equal(t, len(document.Keys), 2)
	assert.Equal(t, document.Keys[0].Kid, nextKid)
	assert.Equal(t, document.Keys[1].Kid, serviceKid)

	// and the mcp set promotes on its own, writing no jwks file of its own
	promotion, err = oauthPromoteAt(vaultHome, "test")
	assert.Equal(t, err, nil)
	assert.Equal(t, promotion.kid, mcpKid)
	_, err = os.Stat(filepath.Join(vaultHome, "test", "oauth-jwks-mcp.json"))
	assert.Equal(t, err != nil, true)
}

// --set names one of the four sets; anything else refuses.
func TestParseOauthSignerKeySet(t *testing.T) {
	for setName, want := range map[string]oauthSignerKeySet{
		"":    oauthSignerKeySetMcp,
		"mcp": oauthSignerKeySetMcp,
		"adm": oauthSignerKeySetAdmin,
		"svc": oauthSignerKeySetService,
		"id":  oauthSignerKeySetId,
	} {
		set, err := parseOauthSignerKeySet(setName)
		assert.Equal(t, err, nil)
		assert.Equal(t, set, want)
	}
	for _, setName := range []string{"admin", "service", "SVC", "svc-"} {
		_, err := parseOauthSignerKeySet(setName)
		assert.Equal(t, err != nil, true)
	}
	assert.Equal(t, oauthSignerKeySetMcp.kidPrefix(), "")
	assert.Equal(t, oauthSignerKeySetId.kidPrefix(), "id-")
	assert.Equal(t, oauthSignerKeySetOfKid("idle-thumbprint"), oauthSignerKeySetMcp)
}

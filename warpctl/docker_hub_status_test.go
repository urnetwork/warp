package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type dockerHubRoundTripFunc func(*http.Request) (*http.Response, error)

func (self dockerHubRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return self(request)
}

type dockerHubResponseStep struct {
	method     string
	path       string
	statusCode int
	body       string
}

func newDockerHubTestClient(t *testing.T, steps ...dockerHubResponseStep) *DockerHubClient {
	t.Helper()

	namespace := "test"
	username := "test-user"
	password := "test-token"
	nextStep := 0
	transport := dockerHubRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if len(steps) <= nextStep {
			return nil, fmt.Errorf("unexpected Docker Hub request %s %s", request.Method, request.URL.Path)
		}
		step := steps[nextStep]
		nextStep += 1
		if request.Method != step.method || request.URL.Path != step.path {
			return nil, fmt.Errorf(
				"Docker Hub request %d was %s %s, expected %s %s",
				nextStep,
				request.Method,
				request.URL.Path,
				step.method,
				step.path,
			)
		}

		recorder := httptest.NewRecorder()
		recorder.Header().Set("Content-Type", "application/json")
		recorder.WriteHeader(step.statusCode)
		_, _ = recorder.Write([]byte(step.body))
		return recorder.Result(), nil
	})
	t.Cleanup(func() {
		if nextStep != len(steps) {
			t.Errorf("received %d Docker Hub requests, expected %d", nextStep, len(steps))
		}
	})

	return &DockerHubClient{
		warpState: &WarpState{
			warpSettings: &WarpSettings{
				DockerNamespace:   &namespace,
				DockerHubUsername: &username,
				DockerHubToken:    &password,
			},
		},
		httpClient: &http.Client{Transport: transport},
		token:      "existing-bearer",
	}
}

func requireDockerHubStatusError(t *testing.T, err error, operation string, statusCode int, privateMarker string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a Docker Hub HTTP status error")
	}
	errorText := err.Error()
	if !strings.Contains(errorText, operation) || !strings.Contains(errorText, fmt.Sprintf("%d", statusCode)) {
		t.Fatalf("unexpected Docker Hub HTTP status error: %q", errorText)
	}
	if strings.Contains(errorText, privateMarker) {
		t.Fatalf("Docker Hub HTTP status error contains response body marker %q", privateMarker)
	}
}

func TestDockerHubLoginRejectsNonSuccessStatus(t *testing.T) {
	const privateMarker = "private-login-response"
	client := newDockerHubTestClient(t, dockerHubResponseStep{
		method:     http.MethodPost,
		path:       "/v2/users/login",
		statusCode: http.StatusUnauthorized,
		body:       `{"token":"must-not-be-used","detail":"private-login-response"}`,
	})
	client.token = ""

	var panicValue any
	func() {
		defer func() {
			panicValue = recover()
		}()
		client.Login()
	}()
	if panicValue == nil {
		t.Fatal("Docker Hub login accepted a non-success HTTP status")
	}
	statusErr, ok := panicValue.(error)
	if !ok {
		t.Fatalf("Docker Hub login panic has unexpected type %T", panicValue)
	}
	requireDockerHubStatusError(t, statusErr, "login", http.StatusUnauthorized, privateMarker)
	if client.token != "" {
		t.Fatalf("Docker Hub login retained token %q from a non-success response", client.token)
	}
}

func TestDockerHubServiceMetaRejectsRepositoryPageStatus(t *testing.T) {
	tests := []struct {
		name          string
		privateMarker string
		statusCode    int
		steps         []dockerHubResponseStep
	}{
		{
			name:          "first page",
			privateMarker: "private-first-repository-page",
			statusCode:    http.StatusServiceUnavailable,
			steps: []dockerHubResponseStep{
				{
					method:     http.MethodGet,
					path:       "/v2/namespaces/test/repositories",
					statusCode: http.StatusServiceUnavailable,
					body:       `{"results":[],"detail":"private-first-repository-page"}`,
				},
			},
		},
		{
			name:          "later page",
			privateMarker: "private-later-repository-page",
			statusCode:    http.StatusTooManyRequests,
			steps: []dockerHubResponseStep{
				{
					method:     http.MethodGet,
					path:       "/v2/namespaces/test/repositories",
					statusCode: http.StatusOK,
					body:       `{"next":"https://hub.docker.com/test/repositories/page-2","results":[{"name":"main-api","status_description":"active"}]}`,
				},
				{
					method:     http.MethodGet,
					path:       "/test/repositories/page-2",
					statusCode: http.StatusTooManyRequests,
					body:       `{"results":[],"detail":"private-later-repository-page"}`,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newDockerHubTestClient(t, test.steps...)
			serviceMeta, err := client.getServiceMeta()
			if serviceMeta != nil {
				t.Fatal("Docker Hub returned partial service metadata after a repository page failed")
			}
			requireDockerHubStatusError(t, err, "repository list", test.statusCode, test.privateMarker)
		})
	}
}

func TestDockerHubServiceMetaRejectsTagPageStatus(t *testing.T) {
	const repositoriesBody = `{"results":[{"name":"main-api","status_description":"active"}]}`
	tests := []struct {
		name          string
		privateMarker string
		statusCode    int
		steps         []dockerHubResponseStep
	}{
		{
			name:          "first page",
			privateMarker: "private-first-tag-page",
			statusCode:    http.StatusServiceUnavailable,
			steps: []dockerHubResponseStep{
				{
					method:     http.MethodGet,
					path:       "/v2/namespaces/test/repositories",
					statusCode: http.StatusOK,
					body:       repositoriesBody,
				},
				{
					method:     http.MethodGet,
					path:       "/v2/namespaces/test/repositories/main-api/tags",
					statusCode: http.StatusServiceUnavailable,
					body:       `{"results":[],"detail":"private-first-tag-page"}`,
				},
			},
		},
		{
			name:          "later page",
			privateMarker: "private-later-tag-page",
			statusCode:    http.StatusBadGateway,
			steps: []dockerHubResponseStep{
				{
					method:     http.MethodGet,
					path:       "/v2/namespaces/test/repositories",
					statusCode: http.StatusOK,
					body:       repositoriesBody,
				},
				{
					method:     http.MethodGet,
					path:       "/v2/namespaces/test/repositories/main-api/tags",
					statusCode: http.StatusOK,
					body:       `{"next":"https://hub.docker.com/test/tags/page-2","results":[{"name":"2026.9.3-1","tag_status":"active","digest":"sha256:test"}]}`,
				},
				{
					method:     http.MethodGet,
					path:       "/test/tags/page-2",
					statusCode: http.StatusBadGateway,
					body:       `{"results":[],"detail":"private-later-tag-page"}`,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newDockerHubTestClient(t, test.steps...)
			serviceMeta, err := client.getServiceMeta()
			if serviceMeta != nil {
				t.Fatal("Docker Hub returned partial service metadata after a tag page failed")
			}
			requireDockerHubStatusError(t, err, "tag list", test.statusCode, test.privateMarker)
		})
	}
}

func TestDockerHubServiceMetaRejectsIncompleteLatestDigest(t *testing.T) {
	const privateDigestMarker = "private-digest-marker"
	tests := []struct {
		name                   string
		semanticVersionResults string
		wantVersionCount       int
	}{
		{
			name:             "unresolved",
			wantVersionCount: 0,
		},
		{
			name: "ambiguous",
			semanticVersionResults: strings.Join([]string{
				`{"name":"2026.9.3-1","tag_status":"active","digest":"private-digest-marker"}`,
				`{"name":"2026.9.3-2","tag_status":"active","digest":"private-digest-marker"}`,
			}, ","),
			wantVersionCount: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := []string{
				`{"name":"g1-latest","tag_status":"active","digest":"private-digest-marker"}`,
			}
			if test.semanticVersionResults != "" {
				results = append(results, test.semanticVersionResults)
			}
			client := newDockerHubTestClient(
				t,
				dockerHubResponseStep{
					method:     http.MethodGet,
					path:       "/v2/namespaces/test/repositories",
					statusCode: http.StatusOK,
					body:       `{"results":[{"name":"main-api","status_description":"active"}]}`,
				},
				dockerHubResponseStep{
					method:     http.MethodGet,
					path:       "/v2/namespaces/test/repositories/main-api/tags",
					statusCode: http.StatusOK,
					body:       fmt.Sprintf(`{"results":[%s]}`, strings.Join(results, ",")),
				},
			)

			serviceMeta, err := client.getServiceMeta()
			if serviceMeta != nil {
				t.Fatal("Docker Hub returned partial service metadata for an incomplete latest digest")
			}
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%d semantic version tags", test.wantVersionCount)) {
				t.Fatalf("unexpected latest-digest resolution error: %v", err)
			}
			if strings.Contains(err.Error(), privateDigestMarker) {
				t.Fatalf("latest-digest resolution error contains digest marker %q", privateDigestMarker)
			}
		})
	}
}

func TestDockerHubServiceMetaAllowsActiveRepositoryWithoutTags(t *testing.T) {
	client := newDockerHubTestClient(
		t,
		dockerHubResponseStep{
			method:     http.MethodGet,
			path:       "/v2/namespaces/test/repositories",
			statusCode: http.StatusOK,
			body:       `{"results":[{"name":"main-api","status_description":"active"}]}`,
		},
		dockerHubResponseStep{
			method:     http.MethodGet,
			path:       "/v2/namespaces/test/repositories/main-api/tags",
			statusCode: http.StatusOK,
			body:       `{"results":[]}`,
		},
	)

	serviceMeta, err := client.getServiceMeta()
	if err != nil {
		t.Fatal(err)
	}
	versionMeta := serviceMeta.envVersionMetas["main"]["api"]
	if versionMeta == nil {
		t.Fatal("active empty repository is missing from service metadata")
	}
	if len(versionMeta.versions) != 0 || len(versionMeta.latestBlocks) != 0 {
		t.Fatalf("active empty repository has unexpected version metadata: %+v", versionMeta)
	}
}

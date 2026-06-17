package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
	"golang.org/x/oauth2"
)

// newRefreshProvider builds a minimal Provider whose token endpoint is tokenURL.
// Only the fields handleRefresh touches on the error paths are populated.
func newRefreshProvider(tokenURL string) *Provider {
	return &Provider{
		OAuthConfig: oauth2.Config{
			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			Endpoint: oauth2.Endpoint{
				TokenURL:  tokenURL,
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		},
	}
}

func refreshRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/refresh", nil)
	req.Header.Set("Authorization", "Bearer 888")
	return req
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	return string(b)
}

func parseOAuthError(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Error string `json:"error"`
	}
	assert.NoError(t, json.Unmarshal([]byte(body), &parsed))
	return parsed.Error
}

// A structured RFC 6749 §5.2 error from the token endpoint (the reported
// invalid_grant case) is forwarded with the provider's real status and a
// normalized JSON body — not collapsed to a bodiless 502.
func TestHandleRefreshStructuredError(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`))
	}))
	defer idp.Close()

	rec := httptest.NewRecorder()
	newRefreshProvider(idp.URL).handleRefresh(rec, refreshRequest())

	res := rec.Result()
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
	assert.Equal(t, "invalid_grant", parseOAuthError(t, readBody(t, res)))
}

// A non-definitive upstream status (e.g. 429 rate-limit) that still carries an
// RFC 6749 error code is forwarded with its real status, so the consumer can
// keep treating it as transient rather than a dead credential.
func TestHandleRefreshForwardsRealStatus(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"rate_limited"}`))
	}))
	defer idp.Close()

	rec := httptest.NewRecorder()
	newRefreshProvider(idp.URL).handleRefresh(rec, refreshRequest())

	res := rec.Result()
	assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
	assert.Equal(t, "rate_limited", parseOAuthError(t, readBody(t, res)))
}

// A non-2xx with no parseable OAuth error code carries nothing useful for the
// consumer's body parser, so it stays on the transient bodiless 502 path.
func TestHandleRefreshBodylessUpstreamErrorIs502(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("<html>nope</html>"))
	}))
	defer idp.Close()

	rec := httptest.NewRecorder()
	newRefreshProvider(idp.URL).handleRefresh(rec, refreshRequest())

	res := rec.Result()
	assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	assert.Equal(t, "", readBody(t, res))
}

// A genuine transport failure (provider unreachable / no HTTP response) still
// returns a bodiless 502.
func TestHandleRefreshTransportErrorIs502(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := idp.URL
	idp.Close() // nothing is listening now

	rec := httptest.NewRecorder()
	newRefreshProvider(closedURL).handleRefresh(rec, refreshRequest())

	res := rec.Result()
	assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	assert.Equal(t, "", readBody(t, res))
}

// A CustomRefresh (Slack/SquadCast) that returns a *RefreshError gets the same
// faithful status + normalized body propagation as the standard path.
func TestHandleRefreshCustomRefreshError(t *testing.T) {
	p := newRefreshProvider("")
	p.CustomRefresh = func(context.Context, oauth2.Config, *oauth2.Token) (*oauth2.Token, error) {
		return nil, &RefreshError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_grant",
			Description: "slack: token_revoked",
			Err:         errors.New("failed refresh"),
		}
	}

	rec := httptest.NewRecorder()
	p.handleRefresh(rec, refreshRequest())

	res := rec.Result()
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
	assert.Equal(t, "invalid_grant", parseOAuthError(t, readBody(t, res)))
}

// A CustomRefresh that returns a plain (non-RefreshError) error is treated as a
// transient failure: bodiless 502.
func TestHandleRefreshCustomRefreshPlainErrorIs502(t *testing.T) {
	p := newRefreshProvider("")
	p.CustomRefresh = func(context.Context, oauth2.Config, *oauth2.Token) (*oauth2.Token, error) {
		return nil, errors.New("boom")
	}

	rec := httptest.NewRecorder()
	p.handleRefresh(rec, refreshRequest())

	res := rec.Result()
	assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	assert.Equal(t, "", readBody(t, res))
}

// Missing bearer token is still a 401, unchanged by the new error handling.
func TestHandleRefreshMissingToken(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/refresh", nil)
	newRefreshProvider("").handleRefresh(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}

package oauth2

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/ssokenizer"
	"github.com/superfly/tokenizer"
	"golang.org/x/oauth2"
)

type Provider struct {
	ssokenizer.ProviderConfig
	OAuthConfig oauth2.Config

	// ForwardParams are the parameters that should be forwarded from the start
	// request to the auth URL.
	ForwardParams []string

	// Params to add to the auth request.
	AuthRequestParams map[string]string

	// Params to add to the token request.
	TokenRequestParams map[string]string

	// CustomExchange, if set, is used in preference to OAuthConfig.Exchange.
	CustomExchange func(context.Context, oauth2.Config, string, ...oauth2.AuthCodeOption) (*oauth2.Token, string, error)

	// CustomRefresh, if set, is used in preference to OAuthConfig.TokenSource refresh.
	CustomRefresh func(context.Context, oauth2.Config, *oauth2.Token) (*oauth2.Token, error)
}

var _ ssokenizer.Provider = (*Provider)(nil)

const (
	startPath    = "/start"
	callbackPath = "/callback"
	refreshPath  = "/refresh"
)

// PC implements the ssokenizer.Provider interface.
func (p *Provider) PC() *ssokenizer.ProviderConfig {
	return &p.ProviderConfig
}

// Validate implements the ssokenizer.Provider interface.
func (p *Provider) Validate() error {
	switch err := p.ProviderConfig.Validate(); {
	case err != nil:
		return err
	case p.OAuthConfig.ClientID == "":
		return errors.New("missing client_id")
	case p.OAuthConfig.ClientSecret == "":
		return errors.New("missing client_secret")
	case p.OAuthConfig.Endpoint.AuthURL == "":
		return errors.New("missing auth_url")
	case p.OAuthConfig.Endpoint.TokenURL == "":
		return errors.New("missing token_url")
	default:
		return nil
	}
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch path := strings.TrimSuffix(r.URL.Path, "/"); path {
	case startPath:
		p.handleStart(w, r)
	case callbackPath:
		p.handleCallback(w, r)
	case refreshPath:
		p.handleRefresh(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (p *Provider) handleStart(w http.ResponseWriter, r *http.Request) {
	defer getLog(r).WithField("status", http.StatusFound).Info()

	tr := ssokenizer.StartTransaction(w, r)
	if tr == nil {
		return
	}

	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}

	// Store forwarded parameters in transaction so they can be used in token exchange
	tr.ForwardedParams = make(map[string]string)
	for _, param := range p.ForwardParams {
		if value := r.URL.Query().Get(param); value != "" {
			opts = append(opts, oauth2.SetAuthURLParam(param, value))
			tr.ForwardedParams[param] = value
		}
	}

	// Re-save transaction with forwarded params
	if len(tr.ForwardedParams) > 0 {
		if err := ssokenizer.SaveTransaction(w, r, tr); err != nil {
			r = withError(r, fmt.Errorf("save transaction: %w", err))
			tr.ReturnError(w, r, "unexpected error")
			return
		}
	}

	for key, value := range p.AuthRequestParams {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}

	if p.OAuthConfig.RedirectURL == "" {
		opts = append(opts, oauth2.SetAuthURLParam("redirect_uri", p.URL.JoinPath(callbackPath).String()))
	}

	url := p.OAuthConfig.AuthCodeURL(tr.Nonce, opts...)
	http.Redirect(w, r, url, http.StatusFound)
}

func (p *Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	tr := ssokenizer.RestoreTransaction(w, r)
	if tr == nil {
		return
	}
	params := r.URL.Query()

	if errParam := params.Get("error"); errParam != "" {
		r = withError(r, fmt.Errorf("error param: %s", errParam))
		tr.ReturnError(w, r, errParam)
		return
	}

	state := params.Get("state")
	if state == "" {
		r = withError(r, errors.New("missing state"))
		tr.ReturnError(w, r, "bad response")
		return
	}

	if subtle.ConstantTimeCompare([]byte(tr.Nonce), []byte(state)) != 1 {
		r = withError(r, errors.New("bad state"))
		r = withFields(r, logrus.Fields{"have": state, "want": tr.Nonce})
		tr.ReturnError(w, r, "bad response")
		return
	}

	code := params.Get("code")
	if code == "" {
		r = withError(r, errors.New("missing code"))
		tr.ReturnError(w, r, "bad response")
		return
	}

	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}

	// Add forwarded parameters from the start request to the token request
	for key, value := range tr.ForwardedParams {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}

	for key, value := range p.TokenRequestParams {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}

	if p.OAuthConfig.RedirectURL == "" {
		opts = append(opts, oauth2.SetAuthURLParam("redirect_uri", p.URL.JoinPath(callbackPath).String()))
	}

	var tok *oauth2.Token
	var metadata string
	var err error

	if p.CustomExchange != nil {
		tok, metadata, err = p.CustomExchange(r.Context(), p.OAuthConfig, code, opts...)
		if err != nil {
			err = fmt.Errorf("failed custom exchange: %w", err)
		}
	} else {
		tok, err = p.OAuthConfig.Exchange(r.Context(), code, opts...)
		if err != nil {
			err = fmt.Errorf("failed exchange: %w", err)
		}
	}
	if err != nil {
		r = withError(r, err)
		tr.ReturnError(w, r, "bad response")
		return
	}
	r = withIdToken(r, tok)

	if t := tok.Type(); t != "Bearer" {
		r = withField(r, "type", t)
		r = withError(r, errors.New("unrecognized token type"))
		tr.ReturnError(w, r, "bad response")
		return
	}

	sealed, err := p.Tokenizer.SealedSecret(&tokenizer.OAuthProcessorConfig{
		Token: &tokenizer.OAuthToken{
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken},
	})
	if err != nil {
		r = withError(r, fmt.Errorf("failed seal: %w", err))
		tr.ReturnError(w, r, "seal error")
		return
	}

	rd := map[string]string{"sealed": sealed}
	if !tok.Expiry.IsZero() {
		rd["expires"] = strconv.FormatInt(tok.Expiry.Unix(), 10)
	}
	if metadata != "" {
		rd["metadata"] = metadata
	}
	tr.ReturnData(w, r, rd)
}

func (p *Provider) handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshTokenString, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		getLog(r).
			WithField("status", http.StatusUnauthorized).
			Info("refresh: missing token")

		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	refreshToken := &oauth2.Token{RefreshToken: refreshTokenString}
	var tok *oauth2.Token
	var err error

	if p.CustomRefresh != nil {
		tok, err = p.CustomRefresh(r.Context(), p.OAuthConfig, refreshToken)
		if err != nil {
			err = fmt.Errorf("failed custom refresh: %w", err)
		}
	} else {
		tok, err = p.OAuthConfig.TokenSource(r.Context(), refreshToken).Token()
		if err != nil {
			err = fmt.Errorf("failed refresh: %w", err)
		}
	}
	if err != nil {
		var re *oauth2.RetrieveError
		var rfe *RefreshError
		switch {
		case errors.As(err, &re) && re.Response != nil && re.ErrorCode != "":
			// Standard path: the provider returned a structured RFC 6749 §5.2
			// error (e.g. 400 invalid_grant). Forward the real upstream status
			// and a normalized error body so callers can tell a dead credential
			// from a transient gateway failure. We reconstruct the body from the
			// already-parsed fields rather than echoing the upstream bytes:
			// ssokenizer is a secret-isolation boundary and must not relay
			// arbitrary upstream content downstream.
			writeRefreshError(w, r, re.Response.StatusCode, re.ErrorCode, re.ErrorDescription, err)
		case errors.As(err, &rfe):
			// Custom refresh (Slack/SquadCast) recognized a definitive,
			// non-retryable OAuth error and normalized it for us.
			writeRefreshError(w, r, rfe.Status, rfe.Code, rfe.Description, err)
		default:
			// No structured error → genuine transport/network failure (we never
			// reached the provider, or it answered unintelligibly). Keep the
			// bodiless 502 so callers treat it as transient.
			getLog(r).
				WithField("status", http.StatusBadGateway).
				WithError(err).
				Info("refresh")

			w.WriteHeader(http.StatusBadGateway)
		}
		return
	}

	r = withIdToken(r, tok)

	if t := tok.Type(); t != "Bearer" {
		getLog(r).
			WithField("status", http.StatusInternalServerError).
			WithField("type", t).
			Info("unrecognized token type")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sealed, err := p.Tokenizer.SealedSecret(&tokenizer.OAuthProcessorConfig{
		Token: &tokenizer.OAuthToken{
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
		},
	})
	if err != nil {
		getLog(r).
			WithField("status", http.StatusInternalServerError).
			WithError(err).
			Info("refresh: failed seal")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", fmt.Sprintf("private, max-age=%d", time.Until(tok.Expiry)/time.Second))

	if _, err := w.Write([]byte(sealed)); err != nil {
		// status already written
		getLog(r).
			WithError(err).
			Info("refresh: write response")

		return
	}

	getLog(r).
		WithField("status", http.StatusOK).
		Info()
}

// RefreshError is returned by a CustomRefresh function to signal that the
// provider gave a structured, definitive OAuth error (a dead credential)
// rather than a transient transport failure. handleRefresh forwards Status and
// Code to the caller so it can stop retrying and prompt a reconnect. Custom
// refresh paths whose providers don't surface a standard *oauth2.RetrieveError
// (e.g. Slack, SquadCast) use this to opt into the same propagation; any error
// that is not a RefreshError falls through to the bodiless 502 transient path.
type RefreshError struct {
	// Status is the HTTP status handleRefresh will return (e.g. 400).
	Status int
	// Code is the RFC 6749 §5.2 error code placed in the response body
	// (e.g. "invalid_grant"). It must contain no secrets.
	Code string
	// Description is an optional, secret-free human-readable detail.
	Description string
	// Err is the underlying error, preserved for logging and unwrapping.
	Err error
}

func (e *RefreshError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Code
}

func (e *RefreshError) Unwrap() error { return e.Err }

// writeRefreshError writes a normalized RFC 6749 §5.2 error response. The body
// is reconstructed from the parsed code/description (never the upstream bytes),
// so no arbitrary provider content crosses the trust boundary, and is marked
// no-store so a transient error is never cached as a credential verdict.
func writeRefreshError(w http.ResponseWriter, r *http.Request, status int, code, description string, err error) {
	getLog(r).
		WithField("status", status).
		WithField("oauth_error", code).
		WithError(err).
		Info("refresh")

	body, jerr := json.Marshal(struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{Error: code, ErrorDescription: description})
	if jerr != nil {
		// Unreachable for plain strings, but never write a partial body.
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, werr := w.Write(body); werr != nil {
		// status already written
		getLog(r).WithError(werr).Info("refresh: write error response")
	}
}

// logging helpers. aliased for convenience
var (
	getLog     = ssokenizer.GetLog
	withError  = ssokenizer.WithError
	withField  = ssokenizer.WithField
	withFields = ssokenizer.WithFields
)

// logging helper. Tries to find and parse user info from id token.
func withIdToken(r *http.Request, tok *oauth2.Token) *http.Request {
	idToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return r
	}

	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return r
	}

	jbody, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return r
	}

	var body struct {
		Sub   string `json:"sub"`
		HD    string `json:"hd"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(jbody, &body); err != nil {
		return r
	}

	if body.Sub != "" {
		r = withField(r, "sub", body.Sub)
	}
	if body.HD != "" {
		r = withField(r, "hd", body.HD)
	}
	if body.Email != "" {
		r = withField(r, "email", body.Email)
	}

	return r
}

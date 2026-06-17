package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	ssooauth2 "github.com/superfly/ssokenizer/oauth2"

	"github.com/slack-go/slack"
	"golang.org/x/oauth2"
)

// A Slack dead-credential error code is normalized to a RefreshError carrying
// invalid_grant so handleRefresh forwards a 400.
func TestSlackRefreshErrorDeadToken(t *testing.T) {
	for _, code := range []string{"invalid_refresh_token", "token_revoked", "token_expired", "account_inactive"} {
		in := slack.SlackErrorResponse{Err: code}
		out := slackRefreshError(in)

		var re *ssooauth2.RefreshError
		if !errors.As(out, &re) {
			t.Fatalf("code %q: expected *RefreshError, got %T", code, out)
		}
		if re.Status != http.StatusBadRequest || re.Code != "invalid_grant" {
			t.Fatalf("code %q: got status=%d code=%q", code, re.Status, re.Code)
		}
	}
}

// A Slack error we don't positively recognize as a dead credential is returned
// unchanged, so it falls through to the transient 502 path.
func TestSlackRefreshErrorUnknownPassesThrough(t *testing.T) {
	in := slack.SlackErrorResponse{Err: "ratelimited"}
	out := slackRefreshError(in)

	var re *ssooauth2.RefreshError
	if errors.As(out, &re) {
		t.Fatalf("expected pass-through, got *RefreshError")
	}
}

func TestSquadcastRefreshDefinitiveError(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		prev := squadcastTokenURL
		squadcastTokenURL = srv.URL

		_, err := squadcastRefresh(context.Background(), oauth2.Config{}, &oauth2.Token{RefreshToken: "x"})

		squadcastTokenURL = prev
		srv.Close()

		var re *ssooauth2.RefreshError
		if !errors.As(err, &re) {
			t.Fatalf("status %d: expected *RefreshError, got %T (%v)", status, err, err)
		}
		if re.Status != http.StatusBadRequest || re.Code != "invalid_grant" {
			t.Fatalf("status %d: got status=%d code=%q", status, re.Status, re.Code)
		}
	}
}

func TestSquadcastRefreshTransientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	prev := squadcastTokenURL
	squadcastTokenURL = srv.URL
	defer func() { squadcastTokenURL = prev }()

	_, err := squadcastRefresh(context.Background(), oauth2.Config{}, &oauth2.Token{RefreshToken: "x"})

	var re *ssooauth2.RefreshError
	if errors.As(err, &re) {
		t.Fatalf("5xx should be transient, got *RefreshError")
	}
	if err == nil {
		t.Fatal("expected an error")
	}
}

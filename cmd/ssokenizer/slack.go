package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/slack-go/slack"
	"golang.org/x/oauth2"
)

// Implements a custom version of oauth.Config.Exchange that handles the additional metadata Slack returns alongside the access/refresh      │
// tokens, and returns it as a gzipped, base64 encoded string after stripping any tokens from it.
func slackExchange(ctx context.Context, conf oauth2.Config, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, string, error) {
	// oauth2.AuthCodeOption.setValue is unexported; apply opts via AuthCodeURL
	// then parse redirect_uri back out of the resulting URL.
	var redirectURL string
	if u, err := url.Parse(conf.AuthCodeURL("", opts...)); err == nil {
		redirectURL = u.Query().Get("redirect_uri")
	}

	r, err := slack.GetOAuthV2ResponseContext(ctx, http.DefaultClient, conf.ClientID, conf.ClientSecret, code, redirectURL)
	if err != nil {
		return nil, "", err
	}
	tok := slackToToken(r)
	r.AccessToken = ""
	r.RefreshToken = ""
	r.AuthedUser.AccessToken = ""  // TODO: no useful way to return this from ssokenizer currently.
	r.AuthedUser.RefreshToken = "" // TODO: no useful way to return this from ssokenizer currently.
	mdB, err := json.Marshal(r)
	if err != nil {
		return nil, "", err
	}
	return tok, base64.StdEncoding.EncodeToString(mdB), nil
}

// Implements a custom version of oauth.Refresh that deals with the fact slack returns a token type other than Bearer which
// the oauth2 package does not like - metadata is not actually used here!
func slackRefresh(ctx context.Context, conf oauth2.Config, refreshToken *oauth2.Token) (*oauth2.Token, error) {
	r, err := slack.RefreshOAuthV2TokenContext(ctx, http.DefaultClient, conf.ClientID, conf.ClientSecret, refreshToken.RefreshToken)
	if err != nil {
		return nil, err
	}
	return slackToToken(r), nil
}

func slackToToken(r *slack.OAuthV2Response) *oauth2.Token {
	tok := oauth2.Token{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
	}
	if r.ExpiresIn != 0 {
		tok.Expiry = time.Now().Add(time.Duration(r.ExpiresIn) * time.Second)
	}
	return &tok
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// Implements a custom version of oauth.Refresh that deals with Squadcast's weird quazi OAuth refresh/token methods...
// the oauth2 package does not like - metadata is not actually used here!
func squadcastRefresh(ctx context.Context, conf oauth2.Config, refreshToken *oauth2.Token) (*oauth2.Token, error) {
	// Use the go HTTP APi to make a request to https://auth.squadcast.com/oauth/access-token passing the provided refresh token
	// as the X-Refresh-Token header.
	req, err := http.NewRequestWithContext(ctx, "GET", "https://auth.squadcast.com/oauth/access-token", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Refresh-Token", refreshToken.RefreshToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var respData struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresAt    int64  `json:"expires_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken:  respData.Data.AccessToken,
		RefreshToken: respData.Data.RefreshToken,
		Expiry:       time.Unix(respData.Data.ExpiresAt, 0),
	}, nil

}

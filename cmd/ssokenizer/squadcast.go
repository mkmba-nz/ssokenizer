package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	ssooauth2 "github.com/superfly/ssokenizer/oauth2"

	"golang.org/x/oauth2"
)

// squadcastTokenURL is the SquadCast refresh endpoint. A var (not a const) so
// tests can point it at a stub server.
var squadcastTokenURL = "https://auth.squadcast.com/oauth/access-token"

// Implements a custom version of oauth.Refresh that deals with Squadcast's weird quazi OAuth refresh/token methods...
// the oauth2 package does not like - metadata is not actually used here!
func squadcastRefresh(ctx context.Context, conf oauth2.Config, refreshToken *oauth2.Token) (*oauth2.Token, error) {
	// Use the go HTTP APi to make a request to squadcastTokenURL passing the provided refresh token
	// as the X-Refresh-Token header.
	req, err := http.NewRequestWithContext(ctx, "GET", squadcastTokenURL, nil)
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
		// SquadCast's error body is undocumented, so we never forward it. A
		// 400/401/403 means it rejected the refresh token itself — a
		// definitive, non-retryable failure that we normalize to 400
		// invalid_grant so the consumer stops retrying and prompts a reconnect.
		// Everything else (429 rate-limit, 5xx, etc.) is treated as transient
		// and left to the bodiless 502 path.
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			return nil, &ssooauth2.RefreshError{
				Status:      http.StatusBadRequest,
				Code:        "invalid_grant",
				Description: fmt.Sprintf("squadcast: status %d", resp.StatusCode),
				Err:         fmt.Errorf("unexpected status code: %d", resp.StatusCode),
			}
		default:
			return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
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

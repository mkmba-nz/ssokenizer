package facebook

import (
	"net/http"

	"github.com/superfly/ssokenizer"
	"github.com/superfly/ssokenizer/oauth2"
	xoauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

type Config struct {
	// OAuth Client ID
	ClientID string

	// OAuth Client secret
	ClientSecret string

	// OAuth scopes to request
	Scopes []string

	// Path where this provider is mounted
	Path string
}

var _ ssokenizer.ProviderConfig = Config{}

func (c Config) Register(sealKey, rpAuth string) (http.Handler, error) {
	return (&oauth2.Config{
		Path: c.Path,
		Config: xoauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			Endpoint:     facebook.Endpoint,
		},
	}).Register(sealKey, rpAuth)
}

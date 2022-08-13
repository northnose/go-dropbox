package dropbox

import (
	"net/http"
)

// Config for the Dropbox clients.
type Config struct {
	HTTPClient  *http.Client
	AccessToken string
        RefreshToken string
        RefreshURL string
}

// NewConfig with the given access token.
func NewConfig(accessToken string, refreshToken string, refreshURL string) *Config {
	return &Config{
		HTTPClient:  http.DefaultClient,
		AccessToken: accessToken,
                RefreshToken: refreshToken,
                RefreshURL: refreshURL,
	}
}

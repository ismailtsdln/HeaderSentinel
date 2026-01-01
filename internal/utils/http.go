package utils

import (
	"crypto/tls"
	"net/http"
	"time"
)

// HTTPClient represents a customized HTTP client.
type HTTPClient struct {
	Client *http.Client
}

// NewHTTPClient creates a new HTTP client with specified timeout and redirect policy.
func NewHTTPClient(timeout time.Duration, followRedirects bool) *HTTPClient {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &HTTPClient{
		Client: client,
	}
}

// Get executes a GET request and returns the response.
func (c *HTTPClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HeaderSentinel/1.0.0")

	return c.Client.Do(req)
}

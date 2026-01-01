package scanner

import (
	"net/http"
	"net/url"
	"strings"
)

// RedirectChain represents a hop in a redirect chain.
type RedirectHop struct {
	URL        string
	StatusCode int
}

// RedirectResult represents the analysis of a redirect chain.
type RedirectResult struct {
	Chain             []RedirectHop
	InsecureDowngrade bool
}

// AnalyzeRedirects trace the redirect chain for a given URL using a custom client.
func AnalyzeRedirects(client *http.Client, startURL string) (RedirectResult, error) {
	result := RedirectResult{
		Chain: []RedirectHop{},
	}

	// Create a dedicated client for redirect tracing to avoid modifying the shared client
	// and to ensure we don't automatically follow redirects.
	tr := &http.Transport{}
	if client.Transport != nil {
		if t, ok := client.Transport.(*http.Transport); ok {
			tr.TLSClientConfig = t.TLSClientConfig
		}
	}

	tracer := &http.Client{
		Transport: tr,
		Timeout:   client.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer tr.CloseIdleConnections()

	currentURL := startURL
	for i := 0; i < 10; i++ { // Limit to 10 redirects
		req, err := http.NewRequest("GET", currentURL, nil)
		if err != nil {
			return result, err
		}
		req.Header.Set("User-Agent", "HeaderSentinel/1.0.0")

		resp, err := tracer.Do(req)
		if err != nil {
			return result, err
		}

		hop := RedirectHop{
			URL:        currentURL,
			StatusCode: resp.StatusCode,
		}
		result.Chain = append(result.Chain, hop)

		location := resp.Header.Get("Location")
		resp.Body.Close() // Close immediately in loop

		if resp.StatusCode >= 300 && resp.StatusCode < 400 && location != "" {
			// Handle relative URLs in Location header
			u, err := url.Parse(location)
			if err != nil {
				break
			}

			if !u.IsAbs() {
				base, err := url.Parse(currentURL)
				if err != nil {
					break
				}
				u = base.ResolveReference(u)
			}

			nextURL := u.String()

			// Detect insecure downgrade
			if strings.HasPrefix(currentURL, "https://") && strings.HasPrefix(nextURL, "http://") {
				result.InsecureDowngrade = true
			}

			currentURL = nextURL
		} else {
			break
		}
	}

	return result, nil
}

package authlib

import (
	"net/http"
	"time"
)

// Client represents an HTTP client that can be used to send requests to the authentication server.
type Client struct {
	BaseURL    string
	HttpClient *http.Client
	ApiKey     string
}

// ErrorResponse represents the structure of an error response
type ErrorResponse struct {
	Message string `json:"message"`
}

func NewClient(baseURL string, apiKey string, httpClient ...*http.Client) *Client {
	var client *http.Client
	if len(httpClient) > 0 {
		client = httpClient[0]
	} else {
		client = &http.Client{
			Timeout: time.Second * 10,
		}
	}

	return &Client{
		BaseURL:    baseURL,
		HttpClient: client,
		ApiKey:     apiKey,
	}
}

func (c *Client) VerifyUserAuthentication(ctx context.Context, token string) (bool, error) {
	// Create a new request to verify user authentication
	verifyURL := fmt.Sprintf("%s/verify", c.BaseURL)
	reqBody, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return false, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check the response status code. If not 200, return an error.
	if resp.StatusCode != http.StatusOK {
		return false, errors.New("failed to verify user authentication")
	}

	// Decode the response body
	var authResponse struct {
		Authenticated bool `json:"authenticated"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return false, fmt.Errorf("failed to decode response body: %w", err)
	}

	return authResponse.Authenticated, nil
}

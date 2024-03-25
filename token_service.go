package authlib

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type TokenService struct {
	PrivateKey ed25519.PrivateKey
	TokenTTL   time.Duration
}

type AuthRequest struct {
	AccountID string `json:"account_id"`
	SecretKey string `json:"secret_key"`
}

type AuthenticateServiceAccountError struct {
	BaseError  error
	StatusCode int
}

func (e *AuthenticateServiceAccountError) Error() string {
	return fmt.Sprintf("authentication failed with status code %d: %v", e.StatusCode, e.BaseError)
}

type AuthResponse struct {
	Token string `json:"token"`
}

func (c *Client) GenerateAccessToken() {}

func (c *Client) ValidateAccessToken() {}

func (c *Client) DecodeAccessToken() {}

// Account represents an entity (user or service account) that can authenticate.
type UserAccount interface {
	GetAccountID() string
	GetCredentials() string
}

// GetTokenForUser sends a request to the auth server to get a token for an account (user or service account).
func (c *Client) GetTokenForUser(ctx context.Context, account UserAccount) (string, error) {
	// Create the JSON request body
	reqBody := AuthRequest{ // This is wrongly referencing service accounts
		AccountID: account.GetAccountID(),
		SecretKey: account.GetCredentials(), // Adjusted to use GetCredentials
	}

	// Marshal the request body to JSON
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/tokens", bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create new request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.ApiKey)

	// Send the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return "", &AuthenticateServiceAccountError{ // This is wrongly referencing service accounts
			BaseError:  errors.New("failed to authenticate account"),
			StatusCode: resp.StatusCode,
		}
	}

	// Decode the response body
	var authResp AuthResponse // This may be wrongly referencing service accounts
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("failed to decode response body: %w", err)
	}

	return authResp.Token, nil
}

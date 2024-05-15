package authlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// LoginInput represents the data required for login
type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginOutput represents the data returned after successful login
type LoginOutput struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Login sends a request to the login endpoint and returns an access token and refresh token on successful login
func (c *Client) Login(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	loginURL := fmt.Sprintf("%s/login", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to login")
	}

	// Decode the response body
	var output LoginOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// VerifyUserAuthentication verifies the user authentication
func (c *Client) VerifyUserAuthentication(ctx context.Context, token string) (bool, error) {
	// Implementation of VerifyUserAuthentication
	// Ensure this function exists and is correct
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

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, errors.New("failed to verify user authentication")
	}

	var authResponse struct {
		Authenticated bool `json:"authenticated"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return false, fmt.Errorf("failed to decode response body: %w", err)
	}

	return authResponse.Authenticated, nil
}

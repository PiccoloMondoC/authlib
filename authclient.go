// sky-auth/pkg/clientlib/authclient/authclient.go
package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/PiccoloMondoC/sky-common/jwt"
	validation "github.com/go-ozzo/ozzo-validation"
)

// Client represents an HTTP client that can be used to send requests to the authentication server.
type Client struct {
	BaseURL    string
	HttpClient *http.Client
}

// User represents the credentials needed to authenticate a user.
type User struct {
	ID       string `json:"id"`
	Password string `json:"password"`
}

// ServiceAccount represents the credentials needed to authenticate a service account.
type ServiceAccount struct {
	AccountID string `json:"account_id"`
	SecretKey string `json:"secret_key"`
}

// Account represents an entity (user or service account) that can authenticate.
type Account interface {
	GetAccountID() string
	GetCredentials() string
}

// AuthResponse represents the JSON response returned from the authentication server after successful authentication.
type AuthResponse struct {
	Token string `json:"token"`
}

// AuthRequest represents the JSON request body sent to the authentication server to authenticate a service account.
type AuthRequest struct {
	AccountID string `json:"account_id"`
	SecretKey string `json:"secret_key"`
}

// PermissionRequest represents the JSON request body sent to the authentication server to check a service account's permissions.
type PermissionRequest struct {
	Token       string `json:"token"`
	Permissions string `json:"permissions"`
}

// PermissionResponse represents the JSON response returned from the authentication server when checking a service account's permissions.
type PermissionResponse struct {
	HasPermission bool `json:"has_permission"`
}

// RegisterServiceAccountRequest represents the JSON request body sent to the authentication server to register a new service account.
type RegisterServiceAccountRequest struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

// RegisterServiceAccountResponse represents the JSON response returned from the authentication server after registering a new service account.
type RegisterServiceAccountResponse struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// This is a custom error type
type CheckUserAuthorizationError struct {
	BaseError  error
	StatusCode int
}

// GetAccountID returns the ID of the user.
func (u User) GetAccountID() string {
	return u.ID
}

// GetCredentials returns the password of the user.
func (u User) GetCredentials() string {
	return u.Password
}

// GetAccountID returns the ID of the service account.
func (sa ServiceAccount) GetAccountID() string {
	return sa.AccountID
}

// GetCredentials returns the secret key of the service account.
func (sa ServiceAccount) GetCredentials() string {
	return sa.SecretKey
}

func (e *CheckUserAuthorizationError) Error() string {
	return fmt.Sprintf("received non-200 response code (%d): %v", e.StatusCode, e.BaseError)
}

// VerifyUserAuthenticationError is a custom error type
type VerifyUserAuthenticationError struct {
	BaseError  error
	StatusCode int
}

func (e *VerifyUserAuthenticationError) Error() string {
	return fmt.Sprintf("received non-200 response code (%d): %v", e.StatusCode, e.BaseError)
}

// This is a custom error type for AuthenticateServiceAccount
type AuthenticateServiceAccountError struct {
	BaseError  error
	StatusCode int
}

func (e *AuthenticateServiceAccountError) Error() string {
	return fmt.Sprintf("received non-200 response code (%d): %v", e.StatusCode, e.BaseError)
}

// RegisterServiceAccountError is a custom error type
type RegisterServiceAccountError struct {
	BaseError  error
	StatusCode int
}

func (e *RegisterServiceAccountError) Error() string {
	return fmt.Sprintf("received non-200 response code (%d): %v", e.StatusCode, e.BaseError)
}

func NewClient(baseURL string, httpClient ...*http.Client) *Client {
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
	}
}

// RegisterServiceAccount registers a new service account with the provided name and roles.
func (c *Client) RegisterServiceAccount(ctx context.Context, name string, roles []string) (string, string, error) {
	// Prepare the request
	registerRequest := RegisterServiceAccountRequest{Name: name, Roles: roles}
	body, err := json.Marshal(registerRequest)
	if err != nil {
		log.Printf("Failed to marshal request body: %v", err)
		return "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/service_account/register", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Failed to create new request: %v", err)
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Handle non-200 status codes
		err = &RegisterServiceAccountError{
			BaseError:  errors.New("received non-200 response code"),
			StatusCode: resp.StatusCode,
		}
		log.Printf("Received non-200 response. StatusCode: %v, Error: %v", resp.StatusCode, err)
		return "", "", err
	}

	// Decode the response
	var registerResponse RegisterServiceAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&registerResponse); err != nil {
		log.Printf("Failed to decode response: %v", err)
		return "", "", err
	}

	log.Printf("Service account registered successfully, ID: %s", registerResponse.ID)
	return registerResponse.ID, registerResponse.Secret, nil
}

// AuthenticateServiceAccount authenticates a service account and returns a JWT token.
func (c *Client) AuthenticateServiceAccount(ctx context.Context, accountID, secretKey string) (string, error) {
	// Prepare the request
	authRequest := AuthRequest{AccountID: accountID, SecretKey: secretKey}
	body, err := json.Marshal(authRequest)
	if err != nil {
		log.Printf("Failed to marshal auth request: %v", err)
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/service_account/authenticate", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Failed to create new request: %v", err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Handle non-200 status codes
		err = &AuthenticateServiceAccountError{
			BaseError:  errors.New("received non-200 response code"),
			StatusCode: resp.StatusCode,
		}
		log.Printf("Received non-200 response. StatusCode: %v, Error: %v", resp.StatusCode, err)
		return "", err
	}

	// Decode the response
	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		log.Printf("Failed to decode response: %v", err)
		return "", err
	}

	return authResponse.Token, nil
}

// VerifyUserAuthentication verifies a JWT token and returns a boolean value indicating whether the token is valid.
func (c *Client) VerifyUserAuthentication(ctx context.Context, token string) (bool, error) {
	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/is-authenticated", nil)
	if err != nil {
		log.Printf("Failed to create new request: %v", err)
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Handle non-200 status codes
		err = &VerifyUserAuthenticationError{
			BaseError:  errors.New("received non-200 response code"),
			StatusCode: resp.StatusCode,
		}
		log.Printf("Received non-200 response. StatusCode: %v, Error: %v", resp.StatusCode, err)
		return false, err
	}

	return resp.StatusCode == http.StatusOK, nil
}

// CheckUserAuthorization verifies a user's authorization to perform a certain action.
func (c *Client) CheckUserAuthorization(ctx context.Context, token, permission string) (bool, error) {
	// Prepare the request
	permissionRequest := PermissionRequest{Token: token, Permissions: permission}
	body, err := json.Marshal(permissionRequest)
	if err != nil {
		log.Printf("Failed to marshal permissionRequest: %v", err)
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/check-permission", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Failed to create new request: %v", err)
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Handle non-200 status codes
		err = &CheckUserAuthorizationError{
			BaseError:  errors.New("received non-200 response code"),
			StatusCode: resp.StatusCode,
		}
		log.Printf("Received non-200 response. StatusCode: %v, Error: %v", resp.StatusCode, err)
		return false, err
	}

	// Decode the response
	var permissionResponse PermissionResponse
	if err := json.NewDecoder(resp.Body).Decode(&permissionResponse); err != nil {
		log.Printf("Failed to decode response: %v", err)
		return false, err
	}

	return permissionResponse.HasPermission, nil
}

// GetTokenForUser sends a request to the auth server to get a token for an account (user or service account).
func (c *Client) GetTokenForUser(ctx context.Context, account Account) (string, error) {
	// Create the JSON request body
	reqBody := AuthRequest{
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

	// Set the content type header
	req.Header.Set("Content-Type", "application/json")

	// Send the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return "", &AuthenticateServiceAccountError{
			BaseError:  errors.New("failed to authenticate account"),
			StatusCode: resp.StatusCode,
		}
	}

	// Decode the response body
	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("failed to decode response body: %w", err)
	}

	return authResp.Token, nil
}

// GetUserIDFromToken extracts the User ID from the given token.
func (c *Client) GetUserIDFromToken(ctx context.Context, token string) (string, error) {
	// Validate input
	err := validation.Validate(
		&token,
		validation.Required,
		validation.By(jwt.IsValidJWT), // use custom JWT validation function
	)
	if err != nil {
		return "", fmt.Errorf("invalid input data: %w", err)
	}

	// Extract user ID from the token
	userID, err := jwt.GetSubject(token)
	if err != nil {
		return "", err
	}

	// In the current system, the subject contains account type and user id separated by an underscore.
	// So, let's split the userID variable and return the user id part.
	userIDParts := strings.Split(userID, "_")
	if len(userIDParts) != 2 {
		return "", fmt.Errorf("invalid subject format in token")
	}

	// return the user id part
	return userIDParts[1], nil
}

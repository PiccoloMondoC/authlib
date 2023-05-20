package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/PiccoloMondoC/sky-auth/internal/logging"
)

// Client represents an HTTP client that can be used to send requests to the authentication server.
type Client struct {
	BaseURL    string
	HttpClient *http.Client
	Logger     *logging.Logger
}

// ServiceAccount represents the credentials needed to authenticate a service account.
type ServiceAccount struct {
	AccountID string `json:"account_id"`
	SecretKey string `json:"secret_key"`
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

func NewClient(baseURL string, logger *logging.Logger, httpClient ...*http.Client) *Client {
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
		Logger:     logger,
	}
}

// RegisterServiceAccount registers a new service account with the provided name and roles.
func (c *Client) RegisterServiceAccount(ctx context.Context, name string, roles []string) (string, string, error) {
	// Log using the custom log wrapper
	logger := c.Logger.GetLoggerWithContextFromContext(ctx).WithFunctionName("RegisterServiceAccount")

	// Prepare the request
	registerRequest := RegisterServiceAccountRequest{Name: name, Roles: roles}
	body, err := json.Marshal(registerRequest)
	if err != nil {
		logger.Error("Failed to marshal request body", "error", err)
		return "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/service_account/register", bytes.NewBuffer(body))
	if err != nil {
		logger.Error("Failed to create new request", "error", err)
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		logger.Error("Failed to send request", "error", err)
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Handle non-200 status codes
		err = &RegisterServiceAccountError{
			BaseError:  errors.New("received non-200 response code"),
			StatusCode: resp.StatusCode,
		}
		logger.Error("Received non-200 response", "statusCode", resp.StatusCode, "error", err)
		return "", "", err
	}

	// Decode the response
	var registerResponse RegisterServiceAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&registerResponse); err != nil {
		logger.Error("Failed to decode response", "error", err)
		return "", "", err
	}

	logger.Info("Service account registered successfully", "id", registerResponse.ID)
	return registerResponse.ID, registerResponse.Secret, nil
}

// AuthenticateServiceAccount authenticates a service account and returns a JWT token.
func (c *Client) AuthenticateServiceAccount(ctx context.Context, accountID, secretKey string) (string, error) {
	// Log using the custom log wrapper
	logger := c.Logger.GetLoggerWithContextFromContext(ctx).WithFunctionName("AuthenticateServiceAccount")

	// Prepare the request
	authRequest := AuthRequest{AccountID: accountID, SecretKey: secretKey}
	body, err := json.Marshal(authRequest)
	if err != nil {
		logger.Error("Failed to marshal auth request", "error", err)
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/service_account/authenticate", bytes.NewBuffer(body))
	if err != nil {
		logger.Error("Failed to create new request", "error", err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		logger.Error("Failed to send request", "error", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Handle non-200 status codes
		err = &AuthenticateServiceAccountError{
			BaseError:  errors.New("received non-200 response code"),
			StatusCode: resp.StatusCode,
		}
		logger.Error("Received non-200 response", "statusCode", resp.StatusCode, "error", err)
		return "", err
	}

	// Decode the response
	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		logger.Error("Failed to decode response", "error", err)
		return "", err
	}

	return authResponse.Token, nil
}

// VerifyUserAuthentication verifies a JWT token and returns a boolean value indicating whether the token is valid.
func (c *Client) VerifyUserAuthentication(ctx context.Context, token string) (bool, error) {
	// Log using the custom log wrapper
	logger := c.Logger.GetLoggerWithContextFromContext(ctx).WithFunctionName("VerifyUserAuthentication")

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/is-authenticated", nil)
	if err != nil {
		logger.Error("Failed to create new request", "error", err)
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		logger.Error("Failed to send request", "error", err)
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Handle non-200 status codes
		err = &VerifyUserAuthenticationError{
			BaseError:  errors.New("received non-200 response code"),
			StatusCode: resp.StatusCode,
		}
		logger.Error("Received non-200 response", "statusCode", resp.StatusCode, "error", err)
		return false, err
	}

	return resp.StatusCode == http.StatusOK, nil
}

// CheckUserAuthorization verifies a user's authorization to perform a certain action.
func (c *Client) CheckUserAuthorization(ctx context.Context, token, permission string) (bool, error) {
	// Log using the custom log wrapper
	logger := c.Logger.GetLoggerWithContextFromContext(ctx).WithFunctionName("CheckUserAuthorization")
	// Prepare the request
	permissionRequest := PermissionRequest{Token: token, Permissions: permission}
	body, err := json.Marshal(permissionRequest)
	if err != nil {
		logger.Error("Failed to marshal permissionRequest", "error", err)
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/check-permission", bytes.NewBuffer(body))
	if err != nil {
		logger.Error("Failed to create new request", "error", err)
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		logger.Error("Failed to send request", "error", err)
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Handle non-200 status codes
		err = &CheckUserAuthorizationError{
			BaseError:  errors.New("received non-200 response code"),
			StatusCode: resp.StatusCode,
		}
		logger.Error("Received non-200 response", "statusCode", resp.StatusCode, "error", err)
		return false, err
	}

	// Decode the response
	var permissionResponse PermissionResponse
	if err := json.NewDecoder(resp.Body).Decode(&permissionResponse); err != nil {
		logger.Error("Failed to decode response", "error", err)
		return false, err
	}

	return permissionResponse.HasPermission, nil
}

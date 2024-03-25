// sky-auth/pkg/clientlib/authlib/service_roles.go
package authlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type ServiceRole struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

type CreateServiceRoleInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (c *Client) CreateServiceRole(ctx context.Context, input CreateServiceRoleInput) (*ServiceRole, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/service-roles", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusCreated {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var newServiceRole ServiceRole
	if err := json.NewDecoder(resp.Body).Decode(&newServiceRole); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &newServiceRole, nil
}

func (c *Client) GetServiceRoleByID(ctx context.Context, id uuid.UUID) (*ServiceRole, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/service-roles/%s", c.BaseURL, id.String())

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var serviceRole ServiceRole
	if err := json.NewDecoder(resp.Body).Decode(&serviceRole); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &serviceRole, nil
}

func (c *Client) GetServiceRoleByName(ctx context.Context, name string) (*ServiceRole, error) {
	// Construct the URL with the service role name
	url := fmt.Sprintf("%s/service-roles/%s", c.BaseURL, name)

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var serviceRole ServiceRole
	if err := json.NewDecoder(resp.Body).Decode(&serviceRole); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &serviceRole, nil
}

func (c *Client) GetServiceRoleIDByName(ctx context.Context, name string) (*uuid.UUID, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/service-roles/"+name, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var response struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &response.ID, nil
}

type UpdateServiceRoleInput struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

func (c *Client) UpdateServiceRole(ctx context.Context, input UpdateServiceRoleInput) (*ServiceRole, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	url := fmt.Sprintf("%s/service-roles/%s", c.BaseURL, input.ID)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var updatedServiceRole ServiceRole
	if err := json.NewDecoder(resp.Body).Decode(&updatedServiceRole); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &updatedServiceRole, nil
}

func (c *Client) DeleteServiceRole(ctx context.Context, roleID uuid.UUID) error {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.BaseURL+"/service-roles/"+roleID.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		return errors.New(errorResponse.Message)
	}

	return nil
}

// ListServiceRolesOutput is the response structure for listing service roles
type ListServiceRolesOutput struct {
	ServiceRoles []ServiceRole `json:"service_roles"`
}

func (c *Client) ListServiceRoles(ctx context.Context) (*ListServiceRolesOutput, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/service-roles", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var output ListServiceRolesOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &output, nil
}

func (c *Client) AssignServicePermissionToServiceRole() {}

func (c *Client) RemoveServicePermissionFromServiceRole() {}

func (c *Client) DoesServiceRoleExist() {}

func (c *Client) GetServiceRolesByServiceAccountIDInServiceRoleModel() {}

func (c *Client) GetServicePermissionsByServiceRoleIDInServiceRoleServicePermissionsModel() {}

func (c *Client) GetServiceRolesByServicePermissionID() {}

func (c *Client) IsServicePermissionAssignedToServiceRole() {}

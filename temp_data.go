// sky-auth/pkg/clientlib/authlib/temp_data.go
package authlib

import (
	"time"

	"github.com/google/uuid"
)

// TemporaryData represents the structure of a temporary data entry
type TemporaryData struct {
	ID        uuid.UUID `json:"id"`
	Data      []byte    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c *Client) CreateTemporaryData() {}

func (c *Client) GetTemporaryData() {}

func (c *Client) UpdateTemporaryData() {}

func (c *Client) DeleteTemporaryData() {}

func (c *Client) ListTemporaryData() {}

func (c *Client) DeleteExpiredTemporaryData() {}

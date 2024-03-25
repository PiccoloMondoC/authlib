// sky-auth/pkg/clientlib/authlib/token_blacklist.go
package authlib

import "time"

// TokenBlacklist represents the structure of a blacklisted token
type TokenBlacklist struct {
	Token     []byte    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

func (c *Client) BlacklistToken() {}

func (c *Client) IsTokenBlacklisted() {}

func (c *Client) RemoveTokenFromBlacklist() {}

func (c *Client) ListBlacklistedTokens() {}

func (c *Client) ClearBlacklist() {}

func (c *Client) CountBlacklistedTokens() {}

func (c *Client) GetBlacklistedTokenDetails() {}

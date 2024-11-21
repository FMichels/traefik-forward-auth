package provider

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// OIDC provider
type OIDC struct {
	IssuerURL                  string `long:"issuer-url" env:"ISSUER_URL" description:"Issuer URL"`
	ClientID                   string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret               string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	ForwardUserClaimsField     string `long:"forward-user-claims-field" env:"FORWARD_USER_CLAIMS_FIELD" description:"Field to forward from user claims to headers"`
	ForwardEmailClaimsField    string `long:"forward-email-claims-field" env:"FORWARD_EMAIL_CLAIMS_FIELD" description:"Field to forward from email claims to headers"`
	ForwardFullNameClaimsField string `long:"forward-fullname-claims-field" env:"FORWARD_FULLNAME_CLAIMS_FIELD" description:"Field to forward from fullname claims to headers"`

	OAuthProvider

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// Name returns the name of the provider
func (o *OIDC) Name() string {
	return "oidc"
}

// Setup performs validation and setup
func (o *OIDC) Setup() error {
	// Check parms
	if o.IssuerURL == "" || o.ClientID == "" || o.ClientSecret == "" {
		return errors.New("providers.oidc.issuer-url, providers.oidc.client-id, providers.oidc.client-secret must be set")
	}

	var err error
	o.ctx = context.Background()

	// Try to initiate provider
	o.provider, err = oidc.NewProvider(o.ctx, o.IssuerURL)
	if err != nil {
		return err
	}

	// Create oauth2 config
	o.Config = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint:     o.provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Create OIDC verifier
	o.verifier = o.provider.Verifier(&oidc.Config{
		ClientID: o.ClientID,
	})

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o *OIDC) GetLoginURL(redirectURI, state string) string {
	return o.OAuthGetLoginURL(redirectURI, state)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o *OIDC) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := o.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("Missing id_token")
	}

	return rawIDToken, nil
}

// GetUser uses the given token and returns a complete provider.User object
func (o *OIDC) GetUser(token string) (User, error) {
	var user User

	// Parse & Verify ID Token
	idToken, err := o.verifier.Verify(o.ctx, token)
	if err != nil {
		return user, err
	}

	var t map[string]interface{}
	if err = idToken.Claims(&t); err != nil {
		return user, err
	}
	if o.ForwardEmailClaimsField != "" {
		user.Email = t[o.ForwardEmailClaimsField].(string)
	} else {
		user.Email = t["email"].(string)
	}
	if o.ForwardFullNameClaimsField != "" {
		user.FullName = t[o.ForwardFullNameClaimsField].(string)
	}
	if o.ForwardUserClaimsField != "" {
		user.User = t[o.ForwardUserClaimsField].(string)
	}

	return user, nil
}

package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// OAuthProvider represents an OAuth2/OIDC provider configuration
type OAuthProvider struct {
	Name         string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	RedirectURL  string
	Scopes       []string

	// Optional: For OIDC/JWT validation
	JWKSURL   string
	PublicKey *rsa.PublicKey
	Audience  string

	// Optional: Custom claim mappings
	UserIDClaim string // Default: "sub"
	EmailClaim  string // Default: "email"
	NameClaim   string // Default: "name"
}

// OAuthConfig holds OAuth configuration for the auth service
type OAuthConfig struct {
	Providers map[string]*OAuthProvider

	// Optional: Callback to handle custom claims or user creation
	OnAuthenticated func(provider string, claims jwt.MapClaims) (*User, error)
}

// OAuth state stored in session
type oauthState struct {
	Provider     string
	State        string
	CodeVerifier string
	ReturnURL    string
}

// StartOAuthFlow initiates the OAuth flow for a provider
func (s *Service) StartOAuthFlow(w http.ResponseWriter, r *http.Request, provider string) error {
	if !s.features.ExternalAuth {
		return ErrFeatureDisabled
	}

	config, exists := s.oauthProviders[provider]
	if !exists {
		return fmt.Errorf("unknown OAuth provider: %s", provider)
	}

	// Generate PKCE pair
	codeVerifier, codeChallenge, err := generatePKCEPair()
	if err != nil {
		return err
	}

	// Generate state
	state := generateRandomState()

	// Store OAuth state in session
	session, _ := s.store.New(r, "oauth-state")
	session.Values["provider"] = provider
	session.Values["state"] = state
	session.Values["code_verifier"] = codeVerifier
	session.Values["return_url"] = r.URL.Query().Get("return_url")
	session.Save(r, w)

	// Build auth URL
	params := url.Values{
		"client_id":             {config.ClientID},
		"redirect_uri":          {config.RedirectURL},
		"response_type":         {"code"},
		"scope":                 {strings.Join(config.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	if config.Audience != "" {
		params.Set("audience", config.Audience)
	}

	authURL := config.AuthURL + "?" + params.Encode()
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)

	return nil
}

// HandleOAuthCallback processes the OAuth callback
func (s *Service) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) error {
	if !s.features.ExternalAuth {
		return ErrFeatureDisabled
	}

	// Get OAuth state from session
	session, err := s.store.Get(r, "oauth-state")
	if err != nil {
		return fmt.Errorf("invalid OAuth session")
	}

	provider, _ := session.Values["provider"].(string)
	sessionState, _ := session.Values["state"].(string)
	codeVerifier, _ := session.Values["code_verifier"].(string)
	// returnURL, _ := session.Values["return_url"].(string)

	// Validate state
	if r.URL.Query().Get("state") != sessionState {
		return fmt.Errorf("invalid OAuth state")
	}

	// Get provider config
	config, exists := s.oauthProviders[provider]
	if !exists {
		return fmt.Errorf("unknown OAuth provider: %s", provider)
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	if code == "" {
		return fmt.Errorf("no authorization code received")
	}

	token, err := s.exchangeCodeForToken(config, code, codeVerifier)
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}

	// Parse ID token if present
	var claims jwt.MapClaims
	if token.IDToken != "" {
		claims, err = s.parseIDToken(config, token.IDToken)
		if err != nil {
			return fmt.Errorf("failed to parse ID token: %w", err)
		}
	}

	// Get or create user
	var user *User
	if s.oauthConfig.OnAuthenticated != nil {
		// Custom handler
		user, err = s.oauthConfig.OnAuthenticated(provider, claims)
	} else {
		// Default handling
		user, err = s.getOrCreateOAuthUser(config, claims)
	}

	if err != nil {
		return fmt.Errorf("failed to process user: %w", err)
	}

	// Create session
	if err := s.CreateSessionForUser(w, r, user.ID, user.Email); err != nil {
		return err
	}

	// Clear OAuth session
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Redirect to return URL or default
	// if returnURL == "" {
	// 	returnURL = "/"
	// }
	// http.Redirect(w, r, returnURL, http.StatusSeeOther)

	return nil
}

// Helper functions

func generatePKCEPair() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	verifier = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)

	h := sha256.Sum256([]byte(verifier))
	challenge = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h[:])

	return
}

func generateRandomState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (s *Service) exchangeCodeForToken(config *OAuthProvider, code, verifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {config.RedirectURL},
		"client_id":     {config.ClientID},
		"code_verifier": {verifier},
	}

	if config.ClientSecret != "" {
		data.Set("client_secret", config.ClientSecret)
	}

	resp, err := http.PostForm(config.TokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
}

func (s *Service) parseIDToken(config *OAuthProvider, idToken string) (jwt.MapClaims, error) {
	// Simple parsing without validation for development
	// In production, would validate with JWKS or public key
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func (s *Service) getOrCreateOAuthUser(config *OAuthProvider, claims jwt.MapClaims) (*User, error) {
	// Extract email
	emailClaim := config.EmailClaim
	if emailClaim == "" {
		emailClaim = "email"
	}

	email, _ := claims[emailClaim].(string)
	if email == "" {
		return nil, fmt.Errorf("no email claim found")
	}

	// Try to find existing user
	user, err := s.findUserByEmail(email)
	if err == nil {
		return user, nil
	}

	// Create new user
	return s.RegisterExternalUser(email)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

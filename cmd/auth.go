package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/net/html"
	"golang.org/x/oauth2"
)

// Simulate a OAuth2 Web Flow in a command line app

const redirectURL = "http://127.0.0.1"

// AuthRequest represents an OAuth2 auth request flow
type AuthRequest struct {
	ClientID     string
	ClientSecret string
	IssuerURL    string
	Username     string
	Password     string
	RootCAs      string

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier

	// Does the provider use "offline_access" scope to request a refresh token
	// or does it use "access_type=offline" (e.g. Google)?
	offlineAsScope bool
	scopes         []string
}

// AuthResponse is the final auth response
type AuthResponse struct {
	AccessToken  string
	TokenType    string
	Expiry       time.Time
	RefreshToken string
}

func oauth2Config(authRequest AuthRequest) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     authRequest.ClientID,
		ClientSecret: authRequest.ClientSecret,
		Endpoint:     authRequest.provider.Endpoint(),
		Scopes:       authRequest.scopes,
		RedirectURL:  redirectURL,
	}
}

type debugTransport struct {
	t http.RoundTripper
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	log.Printf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	log.Printf("%s", respDump)
	return resp, nil
}

func defaultTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func httpClientForSkipTLS() (*http.Client, error) {
	tlsConfig := tls.Config{InsecureSkipVerify: true}

	transport := defaultTransport()
	transport.TLSClientConfig = &tlsConfig

	return &http.Client{
		Transport: transport,
	}, nil
}

// return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(rootCAs string) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	rootCABytes, err := ioutil.ReadFile(rootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to read root-ca: %v", err)
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
	}

	transport := defaultTransport()
	transport.TLSClientConfig = &tlsConfig

	return &http.Client{
		Transport: transport,
	}, nil
}

// Auth will perform an OIDC / OAuth2 handshake without requiring a web browser
func Auth(authRequest AuthRequest) (AuthResponse, error) {
	client := http.DefaultClient
	client.Transport = defaultTransport()
	var err error

	if authRequest.RootCAs != "" {
		client, err = httpClientForRootCAs(authRequest.RootCAs)
		if err != nil {
			return AuthResponse{}, err
		}
	}

	if skipTLS {
		client, err = httpClientForSkipTLS()
		if err != nil {
			return AuthResponse{}, err
		}
	}

	if debugHTTP {
		client.Transport = debugTransport{client.Transport}
	}

	ctx := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(ctx, authRequest.IssuerURL)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("Failed to query provider %q: %v",
			authRequest.IssuerURL, err)
	}

	var s struct {
		// What scopes does a provider support?
		//
		// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := provider.Claims(&s); err != nil {
		return AuthResponse{}, fmt.Errorf("Failed to parse provider scopes_supported: %v", err)
	}

	if len(s.ScopesSupported) == 0 {
		// scopes_supported is a "RECOMMENDED" discovery claim, not a required
		// one. If missing, assume that the provider follows the spec and has
		// an "offline_access" scope.
		authRequest.offlineAsScope = true
	} else {
		// See if scopes_supported has the "offline_access" scope.
		authRequest.offlineAsScope = func() bool {
			for _, scope := range s.ScopesSupported {
				if scope == oidc.ScopeOfflineAccess {
					return true
				}
			}
			return false
		}()
	}

	authRequest.provider = provider
	authRequest.verifier = provider.Verifier(&oidc.Config{ClientID: authRequest.ClientID})

	// Setup complete, start the actual auth
	authRequest.scopes = []string{"openid", "profile", "email", "offline_access"}
	authCodeURL := oauth2Config(authRequest).AuthCodeURL("", oauth2.AccessTypeOffline)

	resp, err := client.Get(authCodeURL)
	if err != nil {
		return AuthResponse{}, err
	}

	defer resp.Body.Close()

	z := html.NewTokenizer(resp.Body)

	var foundReq bool
	var actionLink, reqField string

Loop:
	for {
		tt := z.Next()

		switch {
		case tt == html.ErrorToken:
			// End of the document, we're done
			break Loop
		case tt == html.StartTagToken || tt == html.SelfClosingTagToken:
			t := z.Token()

			switch t.Data {
			case "form":
				for _, a := range t.Attr {
					if a.Key == "action" {
						actionLink = a.Val
						break
					}
				}
			case "input":
				for _, a := range t.Attr {
					if a.Key == "name" && a.Val == "req" {
						foundReq = true
					}
					if foundReq && a.Key == "value" {
						reqField = a.Val
						break
					}
				}
			}
		}
	}

	formValues := url.Values{}
	formValues.Add("req", reqField)
	formValues.Add("login", authRequest.Username)
	formValues.Add("password", authRequest.Password)

	oldRedirectChecker := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(redirectURL, req.RequestURI) {
			return http.ErrUseLastResponse
		}

		return nil
	}

	loginResp, err := client.PostForm(authRequest.IssuerURL+actionLink, formValues)
	if err != nil {
		return AuthResponse{}, err
	}

	defer loginResp.Body.Close()

	approvalLocation, err := loginResp.Location()
	if err != nil {
		return AuthResponse{}, err
	}

	resp, err = client.Get(approvalLocation.String())
	if err != nil {
		return AuthResponse{}, err
	}

	defer resp.Body.Close()

	callbackLocation, err := resp.Location()
	if err != nil {
		return AuthResponse{}, err
	}

	code := callbackLocation.Query().Get("code")

	client.CheckRedirect = oldRedirectChecker

	token, err := oauth2Config(authRequest).Exchange(ctx, code)
	if err != nil {
		return AuthResponse{}, err
	}

	result := AuthResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
	}

	return result, nil
}

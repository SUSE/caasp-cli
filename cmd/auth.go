// Copyright © 2017 SUSE
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
	"io/ioutil"
	"regexp"

	"github.com/coreos/go-oidc"
	"golang.org/x/net/html"
	"golang.org/x/oauth2"
)

// Simulate a OAuth2 Web Flow in a command line app

const redirectURL = "urn:ietf:wg:oauth:2.0:oob"

// AuthRequest represents an OAuth2 auth request flow
type AuthRequest struct {
	ClientID     string
	ClientSecret string
	IssuerURL    string
	Username     string
	Password     string
	RootCA       []byte

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier

	// Does the provider use "offline_access" scope to request a refresh token
	// or does it use "access_type=offline" (e.g. Google)?
	offlineAsScope bool
	scopes         []string
}

// AuthResponse is the final auth response
type AuthResponse struct {
	IDToken      string
	AccessToken  string
	TokenType    string
	Expiry       time.Time
	RefreshToken string
	Scopes       []string
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
	t  http.RoundTripper
	ar AuthRequest
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pws := []string{d.ar.ClientSecret, d.ar.Password}
	stripPasswords := func(str string) string {
		res := str
		for _, s := range pws {
			res = strings.Replace(res, s, "<REDACTED>", -1)
		}

		return res
	}

	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	log.Print(stripPasswords(string(reqDump)))

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	log.Print(stripPasswords(string(respDump)))
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
func httpClientForRootCAs(rootCA []byte) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCA) {
		return nil, fmt.Errorf("no valid certificates found in root CA file")
	}

	transport := defaultTransport()
	transport.TLSClientConfig = &tlsConfig

	return &http.Client{
		Transport: transport,
	}, nil
}

// Auth will perform an OIDC / OAuth2 handshake without requiring a web browser
func Auth(authRequest AuthRequest) (AuthResponse, error) {
	var err error
	var client *http.Client

	if skipTLS {
		client, err = httpClientForSkipTLS()
		if err != nil {
			return AuthResponse{}, err
		}
	} else if len(authRequest.RootCA) > 0 {
		client, err = httpClientForRootCAs(authRequest.RootCA)
		if err != nil {
			return AuthResponse{}, err
		}
	} else {
		client = http.DefaultClient
		client.Transport = defaultTransport()
	}

	if debugHTTP {
		client.Transport = debugTransport{t: client.Transport, ar: authRequest}
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
	authRequest.scopes = []string{"openid", "profile", "email", "offline_access", "groups", "audience:server:client_id:kubernetes"}
	authCodeURL := oauth2Config(authRequest).AuthCodeURL("", oauth2.AccessTypeOffline)

	resp, err := client.Get(authCodeURL)
	if err != nil {
		return AuthResponse{}, err
	}

	defer resp.Body.Close()

	z := html.NewTokenizer(resp.Body)

	var actionLink string

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
			}
		}
	}

	formValues := url.Values{}
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
		return AuthResponse{}, fmt.Errorf("invalid username or password")
	}

	resp, err = client.Get(approvalLocation.String())
	if err != nil {
		return AuthResponse{}, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return AuthResponse{}, err
	}

	r, _ := regexp.Compile("(?:(?:.|\n)*)value=\"(.*?)\"(?:(?:.|\n)*)")

	match := r.FindStringSubmatch(string(body))

	// We expect two matches - the entire body, and then just the code group
	if (len(match) != 2) {
		return AuthResponse{}, fmt.Errorf("failed to extract token from OOB response")
	}

	code := match[1]

	client.CheckRedirect = oldRedirectChecker

	token, err := oauth2Config(authRequest).Exchange(ctx, code)
	if err != nil {
		return AuthResponse{}, err
	}

	result := AuthResponse{
		IDToken:      token.Extra("id_token").(string),
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
		Scopes:       authRequest.scopes,
	}

	return result, nil
}

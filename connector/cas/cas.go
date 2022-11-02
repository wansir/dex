// Package github provides authentication strategies using CAS.
package cas

import (
	"crypto/tls"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	gocas "gopkg.in/cas.v2"
	"gopkg.in/square/go-jose.v2/json"
	"net/http"
	"net/url"
)

type Config struct {
	RedirectURL        string `json:"redirectURL" yaml:"redirectURL"`
	CASServerURL       string `json:"casServerURL" yaml:"casServerURL"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify" yaml:"insecureSkipVerify"`
}

// Open returns a strategy for logging in through GitHub.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {

	casURL, err := url.Parse(c.CASServerURL)
	if err != nil {
		return nil, err
	}
	redirectURL, err := url.Parse(c.RedirectURL)
	if err != nil {
		return nil, err
	}
	cas := casConnector{
		Config: *c,
	}

	cas.client = gocas.NewRestClient(&gocas.RestOptions{
		CasURL:     casURL,
		ServiceURL: redirectURL,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify},
			},
		},
		URLScheme: nil,
	})
	return &cas, nil
}

var (
	_ connector.CASConnector = (*casConnector)(nil)
)

type casConnector struct {
	Config
	client *gocas.RestClient
}

func (c *casConnector) LoginURL() (string, error) {
	return fmt.Sprintf("%s/login?service=%s", c.CASServerURL, c.RedirectURL), nil
}

type UserEntry struct {
	Mobile string `json:"mobile"`
}

func (c *casConnector) HandleCallback(r *http.Request) (identity connector.Identity, err error) {
	// CAS callback, see also https://apereo.github.io/cas/6.3.x/protocol/CAS-Protocol-V2-Specification.html#25-servicevalidate-cas-20
	ticket := r.URL.Query().Get("ticket")
	resp, err := c.client.ValidateServiceTicket(gocas.ServiceTicket(ticket))
	if err != nil {
		return identity, fmt.Errorf("cas: failed to validate service ticket : %v", err)
	}
	uid := resp.User
	var user UserEntry
	_ = json.Unmarshal([]byte(resp.Attributes.Get("userDetail")), &user)
	if user.Mobile != "" {
		uid = user.Mobile
	}

	identity = connector.Identity{
		UserID:            uid,
		Username:          resp.User,
		PreferredUsername: resp.User,
		Email:             resp.Attributes.Get("email"),
		EmailVerified:     true,
	}
	return identity, nil
}

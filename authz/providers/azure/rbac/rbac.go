/*
Copyright The Guard Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package rbac

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/appscode/guard/auth/providers/azure/graph"
	jsoniter "github.com/json-iterator/go"
)

// These are the base URL endpoints for MS graph
var (
	json = jsoniter.ConfigCompatibleWithStandardLibrary
)

// UserInfo allows you to get user data from MS Graph
type AccessInfo struct {
	headers http.Header
	client  *http.Client
	expires time.Time
	// These allow us to mock out the URL for testing
	apiURL *url.URL

	accessAllowed bool
	tokenProvider graph.TokenProvider
}

type CheckAccess struct {
	Attributes 
}

func newAccessInfo(tokenProvider graph.TokenProvider, rbacURL *url.URL, useGroupUID bool) (*AccessInfo, error) {
	u := &AccessInfo{
		client: http.DefaultClient,
		headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		apiURL:        rbacURL,
		tokenProvider: tokenProvider,
	}

	return u, nil
}

func New(clientID, clientSecret, tenantID string, useGroupUID bool, aadEndpoint, msrbacHost string) (*AccessInfo, error) {
	rbacEndpoint := "https://" + msrbacHost + "/"
	rbacURL, _ := url.Parse(rbacEndpoint + "v1.0")

	tokenProvider := graph.NewClientCredentialTokenProvider(clientID, clientSecret,
		fmt.Sprintf("%s%s/oauth2/v2.0/token", aadEndpoint, tenantID),
		fmt.Sprintf("https://%s/.default", msrbacHost))

	return newAccessInfo(tokenProvider, rbacURL, useGroupUID)
}

func (a *AccessInfo) checkAccess(userPrincipal string) ([]string, error) {



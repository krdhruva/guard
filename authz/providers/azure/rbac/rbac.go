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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/appscode/guard/auth/providers/azure/graph"
	"github.com/golang/glog"
	"github.com/moul/http2curl"
	"github.com/pkg/errors"
	authzv1 "k8s.io/api/authorization/v1"
)

var (
	MANAGED_CLUSTER   = "Microsoft.ContainerService/managedClusters"
	CONNECTED_CLUSTER = "Microsoft.Kubernetes/connectedClusters"
)

const (
	expiryDelta = 60 * time.Second
)

// AccessInfo allows you to get user data from MS Graph
type AccessInfo struct {
	headers http.Header
	client  *http.Client
	expires time.Time
	// These allow us to mock out the URL for testing
	apiURL *url.URL

	tokenProvider   graph.TokenProvider
	clusterType     string
	azureResourceId string
}

func newAccessInfo(tokenProvider graph.TokenProvider, rbacURL *url.URL, useGroupUID bool, clsuterType, resourceId string) (*AccessInfo, error) {
	u := &AccessInfo{
		client: http.DefaultClient,
		headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		apiURL:          rbacURL,
		tokenProvider:   tokenProvider,
		azureResourceId: resourceId}

	if clsuterType == "arc" {
		u.clusterType = CONNECTED_CLUSTER
	}

	if clsuterType == "aks" {
		u.clusterType = MANAGED_CLUSTER
	}

	return u, nil
}

func New(clientID, clientSecret, tenantID string, useGroupUID bool, aadEndpoint, msrbacHost, clusterType, resourceId string) (*AccessInfo, error) {
	rbacURL, _ := url.Parse(msrbacHost)

	tokenProvider := graph.NewClientCredentialTokenProvider(clientID, clientSecret,
		aadEndpoint+tenantID+"/oauth2/v2.0/token",
		msrbacHost+".default")

	return newAccessInfo(tokenProvider, rbacURL, useGroupUID, clusterType, resourceId)
}

func NewWithAKS(tokenURL, tenantID, msrbacHost, clusterType, resourceId string) (*AccessInfo, error) {
	rbacEndpoint := "https://" + msrbacHost + "/"
	rbacURL, _ := url.Parse(rbacEndpoint)

	tokenProvider := graph.NewAKSTokenProvider(tokenURL, tenantID)

	return newAccessInfo(tokenProvider, rbacURL, true, clusterType, resourceId)
}

func (a *AccessInfo) RefreshToken() error {
	resp, err := a.tokenProvider.Acquire(graph.TokenOption{"", ""})
	if err != nil {
		return errors.Errorf("%s: failed to refresh token: %s", a.tokenProvider.Name(), err)
	}

	// Set the authorization headers for future requests
	a.headers.Set("Authorization", fmt.Sprintf("Bearer %s", resp.Token))
	expIn := time.Duration(resp.Expires) * time.Second
	a.expires = time.Now().Add(expIn - expiryDelta)

	return nil
}

func (a *AccessInfo) IsTokenExpired() bool {
	if a.expires.Before(time.Now()) {
		return true
	} else {
		return false
	}
}

func (a *AccessInfo) CheckAccess(request *authzv1.SubjectAccessReviewSpec) (*authzv1.SubjectAccessReviewStatus, error) {
	var API_VERSION string = "2018-09-01-preview"
	checkAccessBody := PrepareCheckAccessRequest(request, a.clusterType, a.azureResourceId)
	checkAccessURL := *a.apiURL
	// Append the path for azure cluster resource id
	checkAccessURL.Path = path.Join(checkAccessURL.Path, a.azureResourceId)
	var str string
	if getNameSpaceScope(request, &str) {
		checkAccessURL.Path = path.Join(checkAccessURL.Path, str)
	}

	checkAccessURL.Path = path.Join(checkAccessURL.Path, "/providers/Microsoft.Authorization/checkaccess")
	params := url.Values{}
	params.Add("api-version", API_VERSION)
	checkAccessURL.RawQuery = params.Encode()

	if a.IsTokenExpired() {
		a.RefreshToken()
	}

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(checkAccessBody); err != nil {
		return nil, errors.Wrap(err, "error encoding check access request")
	}

	binaryData, _ := json.MarshalIndent(checkAccessBody, "", "    ")
	fmt.Printf("binary data:%s", binaryData)

	req, err := http.NewRequest(http.MethodPost, checkAccessURL.String(), buf)
	if err != nil {
		return nil, errors.Wrap(err, "error creating check access request")
	}
	// Set the auth headers for the request
	req.Header = a.headers

	if glog.V(10) {
		cmd, _ := http2curl.GetCurlCommand(req)
		glog.V(10).Infoln(cmd)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error getting check access result")
	}
	defer resp.Body.Close()

	data, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("response:%s", data)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("request failed %s with status code %d and response is %s", req.URL.String(), resp.StatusCode, string(data))
		if resp.StatusCode == http.StatusTooManyRequests {
			glog.V(10).Infoln("Moving to another ARM instance!")
			a.client.CloseIdleConnections()
			//to-do retry for this
			// add metrix for this scenario
			return nil, errors.Errorf("request %s failed with status code: %d and response: %s", req.URL.Path, resp.StatusCode, string(data))
		}

		if resp.StatusCode >= http.StatusInternalServerError {
			return &authzv1.SubjectAccessReviewStatus{Allowed: false, Reason: "server error", Denied: false}, nil
		}

	} else {
		remaining := resp.Header.Get("x-ms-ratelimit-remaining-subscription-reads")
		glog.Infoln("Remaining request count in ARM instance:" + remaining)
		count, _ := strconv.Atoi(remaining)
		if count < 2000 {
			if glog.V(10) {
				glog.V(10).Infoln("Moving to another ARM instance!")
			}
			a.client.CloseIdleConnections()
		}
	}

	// Decode response and prepare k8s response
	return ConvertCheckAccessResponse(data)
}

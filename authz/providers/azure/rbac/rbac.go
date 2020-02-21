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
	"path"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	"github.com/appscode/guard/auth/providers/azure/graph"	
	jsoniter "github.com/json-iterator/go"
)

// These are the base URL endpoints for MS graph
var (
	json = jsoniter.ConfigCompatibleWithStandardLibrary
	MANAGED_CLUSTER = "Microsoft.ContainerService/managedClusters/"
	CONNECTED_CLUSTER = "Microsoft.Kubernetes/connectedClusters/"
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
	clusterType string
	azureResourceId string
}

func newAccessInfo(tokenProvider graph.TokenProvider, rbacURL *url.URL, useGroupUID bool, clsuterType, resourceId string) (*AccessInfo, error) {
	u := &AccessInfo{
		client: http.DefaultClient,
		headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		apiURL:        rbacURL,
		tokenProvider: tokenProvider,		
		resourceId: resourceId
	}

	if clsuterType == "arc" {
		u.clusterType = CONNECTED_CLUSTER
	}

	if clsuterType == "aks" {
		u.clusterType = MANAGED_CLUSTER
	}

	return u, nil
}

func New(clientID, clientSecret, tenantID string, useGroupUID bool, aadEndpoint, msrbacHost, clusterType, resourceId string) (*AccessInfo, error) {
	rbacEndpoint := "https://" + msrbacHost + "/"
	rbacURL, _ := url.Parse(rbacEndpoint)

	tokenProvider := graph.NewClientCredentialTokenProvider(clientID, clientSecret,
		fmt.Sprintf("%s%s/oauth2/v2.0/token", aadEndpoint, tenantID),
		fmt.Sprintf("https://%s/.default", msrbacHost))

	return newAccessInfo(tokenProvider, rbacURL, useGroupUID, clusterType)
}

func NewWithAKS(tokenURL, tenantID, msrbacHost, clusterType string) (*AccessInfo, error) {
	rbacEndpoint := "https://" + msrbacHost + "/"
	rbacURL, _ := url.Parse(rbacEndpoint)

	tokenProvider := graph.NewAKSTokenProvider(tokenURL, tenantID)

	return newAccessInfo(tokenProvider, rbacURL, true, clusterType)
}

func (a *AccessInfo) CheckAccess(request *authzv1.SubjectAccessReviewSpec) (*authzv1.SubjectAccessReviewStatus, error) {
	req := PrepareCheckAccessRequest(request, MANAGED_CLUSTER, azureResourceId)

	checkAccessURL := *a.apiURL
	// Append the path for azure cluster resource id 
	checkAccessURL.Path = path.Join(checkAccessURL.Path, azureResourceId, getNameSpaceScoe(request), "/providers/Microsoft.Authorization/checkaccess?api-version=2018-09-01-preview"))

	// The body being sent makes sure that all groups are returned, not just security groups
	req, err := http.NewRequest(http.MethodPost, checkAccessURL.String(), strings.NewReader(`{"securityEnabledOnly": false}`))
	if err != nil {
		return nil, errors.Wrap(err, "error creating check access request")
	}
	// Set the auth headers for the request
	req.Header = u.headers

	if glog.V(10) {
		cmd, _ := http2curl.GetCurlCommand(req)
		glog.V(10).Infoln(cmd)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error getting check access result")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("request %s failed with status code: %d and response: %s", req.URL.Path, resp.StatusCode, string(data))
	}

	// Decode response and prepare k8s response
	var objects = ObjectList{}
	err = json.NewDecoder(resp.Body).Decode(&objects)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode response for request %s", req.URL.Path)
	}
}

func (a *AccessInfo) RefreshToken() error {
	resp, err := a.tokenProvider.Acquire()
	if err != nil {
		return errors.Errorf("%s: failed to refresh token: %s", u.tokenProvider.Name(), err)
	}

	// Set the authorization headers for future requests
	u.headers.Set("Authorization", fmt.Sprintf("Bearer %s", resp.Token))
	expIn := time.Duration(resp.Expires) * time.Second
	u.expires = time.Now().Add(expIn - expiryDelta)

	return nil
}


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

package graph

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.kubeguard.dev/guard/util/httpclient"

	jsoniter "github.com/json-iterator/go"
	"github.com/moul/http2curl"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"k8s.io/klog/v2"
)

// These are the base URL endpoints for MS graph
var (
	json                  = jsoniter.ConfigCompatibleWithStandardLibrary
	expandedGroupsPerCall = 500

	getMemberGroupsFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "guard_azure_graph_failure_total",
		Help: "Azure graph getMemberGroups call failed.",
	})
)

const (
	expiryDelta = 60 * time.Second
	getterName  = "ms-graph"
)

// UserInfo allows you to get user data from MS Graph
type UserInfo struct {
	headers http.Header
	client  *http.Client
	expires time.Time
	// These allow us to mock out the URL for testing
	apiURL *url.URL

	groupsPerCall int
	useGroupUID   bool

	tokenProvider TokenProvider
}

func (u *UserInfo) getGroupIDs(ctx context.Context, userPrincipal string) ([]string, error) {
	// Create a new request for finding the user.
	// Shallow copy of the base API URL
	userSearchURL := *u.apiURL
	// Append the path for the member list
	userSearchURL.Path = path.Join(userSearchURL.Path, fmt.Sprintf("/users/%s/getMemberGroups", userPrincipal))

	// The body being sent makes sure that all groups are returned, not just security groups
	req, err := http.NewRequest(http.MethodPost, userSearchURL.String(), strings.NewReader(`{"securityEnabledOnly": false}`))
	if err != nil {
		return nil, errors.Wrap(err, "error creating group IDs request")
	}
	// Set the auth headers for the request
	req.Header = u.headers

	resp, err := u.client.Do(req.WithContext(ctx))
	if err != nil {
		getMemberGroupsFailed.Inc()
		return nil, errors.Wrap(err, "error listing users")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("request %s failed with status code: %d and response: %s", req.URL.Path, resp.StatusCode, string(data))
	}

	// Decode the group response
	objects := ObjectList{}
	err = json.NewDecoder(resp.Body).Decode(&objects)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode response for request %s", req.URL.Path)
	}
	return objects.Value, nil
}

func (u *UserInfo) getExpandedGroups(ctx context.Context, ids []string) (*GroupList, error) {
	// Encode the ids into the request body
	body := &bytes.Buffer{}
	err := json.NewEncoder(body).Encode(ObjectQuery{
		IDs:   ids,
		Types: []string{"group"},
	})
	if err != nil {
		return nil, errors.Wrap(err, "error encoding body")
	}

	// Set up the request
	// Shallow copy of the base API URL
	groupObjectsURL := *u.apiURL
	// Append the path for the group expansion
	groupObjectsURL.Path = path.Join(groupObjectsURL.Path, "/directoryObjects/getByIds")
	req, err := http.NewRequest(http.MethodPost, groupObjectsURL.String(), body)
	if err != nil {
		return nil, errors.Wrap(err, "error creating group expansion request")
	}
	// Set the auth headers
	req.Header = u.headers

	if klog.V(10).Enabled() {
		cmd, _ := http2curl.GetCurlCommand(req)
		klog.V(10).Infoln(cmd)
	}

	resp, err := u.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "error expanding groups")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("request %s failed with status code: %d and response: %s", req.URL.Path, resp.StatusCode, string(data))
	}

	// Decode the response
	groups := &GroupList{}
	err = json.NewDecoder(resp.Body).Decode(groups)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode response for request %s", req.URL.Path)
	}
	return groups, nil
}

func (u *UserInfo) GetMemberGroupsUsingARCOboService(ctx context.Context, tenantID string, resourceID string, accessToken string) ([]string, error) {
	reqBody := struct {
		TenantID    string `json:"tenantID"`
		AccessToken string `json:"accessToken"`
	}{
		TenantID:    tenantID,
		AccessToken: accessToken,
	}

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(reqBody); err != nil {
		return nil, errors.Wrap(err, "failed to encode token request")
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://eus.obo.arc.azure.com:8084%s/%s", resourceID, "getMemberGroups"), buf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create getMemberGroups request")
	}
	// Set the auth headers
	req.Header = u.headers

	correlationID := uuid.New()
	req.Header.Set("x-ms-correlation-request-id", correlationID.String())
	resp, err := u.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "failed to send  getMemberGroups request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("request failed with status code: %d and response: %s", resp.StatusCode, string(data))
	}

	// Decode the response
	groups := &GroupList{}
	var groupNames []string
	err = json.NewDecoder(resp.Body).Decode(groups)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode response for request %s", req.URL.Path)
	}

	// Extract out the Group objects into a list of strings
	for i := 0; i < len(groups.Value); i++ {
		groupNames = append(groupNames, groups.Value[i].Name)
	}

	return groupNames, nil
}

func (u *UserInfo) RefreshToken(ctx context.Context, token string) error {
	resp, err := u.tokenProvider.Acquire(ctx, token)
	if err != nil {
		return errors.Errorf("%s: failed to refresh token: %s", u.tokenProvider.Name(), err)
	}

	// Set the authorization headers for future requests
	u.headers.Set("Authorization", fmt.Sprintf("Bearer %s", resp.Token))
	expIn := time.Duration(resp.Expires) * time.Second
	u.expires = time.Now().Add(expIn - expiryDelta)

	return nil
}

// GetGroups gets a list of all groups that the given user principal is part of
// Generally in federated directories the email address is the userPrincipalName
func (u *UserInfo) GetGroups(ctx context.Context, userPrincipal string) ([]string, error) {
	// Get the group IDs for the user
	groupIDs, err := u.getGroupIDs(ctx, userPrincipal)
	if err != nil {
		return nil, err
	}

	if u.useGroupUID {
		return groupIDs, nil
	}

	totalGroups := len(groupIDs)
	klog.V(10).Infof("totalGroups: %d", totalGroups)

	groupNames := make([]string, 0, totalGroups)
	for i := 0; i < totalGroups; i += u.groupsPerCall {
		startIndex := i
		endIndex := min(i+u.groupsPerCall, totalGroups)
		klog.V(10).Infof("Getting group names for IDs between startIndex: %d and endIndex: %d", startIndex, endIndex)

		// Expand the group IDs
		groups, err := u.getExpandedGroups(ctx, groupIDs[startIndex:endIndex])
		if err != nil {
			return nil, err
		}
		// Extract out the Group objects into a list of strings
		for i := 0; i < len(groups.Value); i++ {
			groupNames = append(groupNames, groups.Value[i].Name)
		}
	}

	return groupNames, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Name returns the name of this getter
func (u *UserInfo) Name() string {
	return getterName
}

// newUserInfo returns a UserInfo object
func newUserInfo(tokenProvider TokenProvider, graphURL *url.URL, useGroupUID bool) (*UserInfo, error) {
	u := &UserInfo{
		client: httpclient.DefaultHTTPClient,
		headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		apiURL:        graphURL,
		groupsPerCall: expandedGroupsPerCall,
		useGroupUID:   useGroupUID,
		tokenProvider: tokenProvider,
	}

	return u, nil
}

// New returns a new UserInfo object
func New(clientID, clientSecret, tenantID string, useGroupUID bool, aadEndpoint, msgraphHost string) (*UserInfo, error) {
	graphEndpoint := "https://" + msgraphHost + "/"
	graphURL, _ := url.Parse(graphEndpoint + "v1.0")

	tokenProvider := NewClientCredentialTokenProvider(clientID, clientSecret,
		fmt.Sprintf("%s%s/oauth2/v2.0/token", aadEndpoint, tenantID),
		fmt.Sprintf("https://%s/.default", msgraphHost))

	return newUserInfo(tokenProvider, graphURL, useGroupUID)
}

// NewWithOBO returns a new UserInfo object
func NewWithOBO(clientID, clientSecret, tenantID string, aadEndpoint, msgraphHost string) (*UserInfo, error) {
	graphEndpoint := "https://" + msgraphHost + "/"
	graphURL, _ := url.Parse(graphEndpoint + "v1.0")

	tokenProvider := NewOBOTokenProvider(clientID, clientSecret,
		fmt.Sprintf("%s%s/oauth2/v2.0/token", aadEndpoint, tenantID),
		fmt.Sprintf("https://%s/.default", msgraphHost))

	return newUserInfo(tokenProvider, graphURL, true)
}

// NewWithAKS returns a new UserInfo object used in AKS
func NewWithAKS(tokenURL, tenantID, msgraphHost string) (*UserInfo, error) {
	graphEndpoint := "https://" + msgraphHost + "/"
	graphURL, _ := url.Parse(graphEndpoint + "v1.0")

	tokenProvider := NewAKSTokenProvider(tokenURL, tenantID)

	return newUserInfo(tokenProvider, graphURL, true)
}

// NewWithARC returns a new UserInfo object used in ARC
func NewWithARC(msiAudience string, armID string) (*UserInfo, error) {
	graphURL, _ := url.Parse("")
	tokenProvider := NewMSITokenProvider(msiAudience, MSIEndpointForARC, armID)

	return newUserInfo(tokenProvider, graphURL, false)
}

func TestUserInfo(clientID, clientSecret, loginUrl, apiUrl string, useGroupUID bool) (*UserInfo, error) {
	parsedApi, err := url.Parse(apiUrl)
	if err != nil {
		return nil, err
	}
	u := &UserInfo{
		client: httpclient.DefaultHTTPClient,
		headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		apiURL:        parsedApi,
		groupsPerCall: expandedGroupsPerCall,
		useGroupUID:   useGroupUID,
	}
	u.tokenProvider = NewClientCredentialTokenProvider(clientID, clientSecret, loginUrl, "")
	if err != nil {
		return nil, err
	}

	return u, nil
}

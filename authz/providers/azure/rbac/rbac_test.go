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
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"
)

func getAPIServerAndAccessInfo(returnCode int, body, clusterType, resourceId string) (*httptest.Server, *AccessInfo) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(returnCode)
		_, _ = w.Write([]byte(body))
	}))
	apiURL, _ := url.Parse(ts.URL)
	u := &AccessInfo{
		client:          http.DefaultClient,
		apiURL:          apiURL,
		headers:         http.Header{},
		expiresAt:       time.Now().Add(time.Hour),
		clusterType:     clusterType,
		azureResourceId: resourceId,
		armCallLimit:    0,
		dataStore:       nil}
	return ts, u
}

/*
func TestCheckAccess(t *testing.T) {
	t.Run("successful request", func(t *testing.T) {
		var validBody = `{
  "value": [
      "f36ec2c5-fa5t-4f05-b87f-deadbeef"
  ]
}`
		ts, u := getAPIServerAndUserInfo(http.StatusOK, validBody, "aks", "resourceid")
		defer ts.Close()

		groups, err := u.getGroupIDs("john.michael.kane@yacht.io")
		if err != nil {
			t.Errorf("Should not have gotten error: %s", err)
		}
		if len(groups) != 1 {
			t.Errorf("Should have gotten a list of group IDs with 1 entry. Got: %d", len(groups))
		}
	})

	//scenarios: bad check access body - encoding issue
	// error in http request
	// http client Do return error
	// return code 200, 429, other

	t.Run("bad server response", func(t *testing.T) {
		ts, u := getAPIServerAndUserInfo(http.StatusInternalServerError, "shutdown")
		defer ts.Close()

		groups, err := u.getGroupIDs("alexander.conklin@cia.gov")
		if err == nil {
			t.Error("Should have gotten error")
		}
		if groups != nil {
			t.Error("Group list should be nil")
		}
	})
	t.Run("request error", func(t *testing.T) {
		badURL, _ := url.Parse("https://127.0.0.1:34567")
		u := &UserInfo{
			client:        http.DefaultClient,
			apiURL:        badURL,
			headers:       http.Header{},
			expires:       time.Now().Add(time.Hour),
			groupsPerCall: expandedGroupsPerCall,
		}

		groups, err := u.getGroupIDs("richard.webb@cia.gov")
		if err == nil {
			t.Error("Should have gotten error")
		}
		if groups != nil {
			t.Error("Group list should be nil")
		}
	})
	t.Run("bad response body", func(t *testing.T) {
		ts, u := getAPIServerAndUserInfo(http.StatusOK, "{bad_json")
		defer ts.Close()

		groups, err := u.getGroupIDs("nicky.parsons@cia.gov")
		if err == nil {
			t.Error("Should have gotten error")
		}
		if groups != nil {
			t.Error("Group list should be nil")
		}
	})
}
*/

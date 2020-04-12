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

	"github.com/appscode/guard/authz/providers/azure/data"
)

func getAPIServerAndAccessInfo(returnCode int, body, clusterType, resourceId string, dataStore *data.DataStore) (*httptest.Server, *AccessInfo) {
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
		dataStore:       dataStore}
	return ts, u
}


func TestCheckAccess(t *testing.T) {
	t.Run("successful request", func(t *testing.T) {
		var validBody = `[
			{
				"accessDecision": "Allowed",
				"actionId": "Microsoft.Kubernetes/connectedClusters/api/read",
				"isDataAction": true,
				"roleAssignment": {
					"DelegatedManagedIdentityResourceId": "",
					"Id": "2356a662cf2d43a6a63ec09edd297e6a",
					"RoleDefinitionId": "456aab9a7f234dae8a7b4cfdb999545e",
					"PrincipalId": "53d5f1372fae4bf591d1d420e323c6a9",
					"PrincipalType": "Group",
					"Scope": "/subscriptions/7cbe213b-b960-4db1-872a-c26d4993d995/resourceGroups/KDRG/providers/Microsoft.Kubernetes/connectedClusters/KSD-Test4",
					"Condition": "",
					"ConditionVersion": "",
					"CanDelegate": false
				},
				"denyAssignment": {
					"IsSystemProtected": "",
					"Id": "",
					"Name": "",
					"Description": "",
					"Scope": "",
					"DoNotApplyToChildScopes": false,
					"Condition": "",
					"ConditionVersion": ""
				},
				"timeToLiveInMs": 300000
			}
		]`

		var TestOptions = Options {
			HardMaxCacheSize:   1,
			Shards:             1,
			LifeWindow:         1 * time.Minute,
			CleanWindow:        1 * time.Minute,
			MaxEntriesInWindow: 10,
			MaxEntrySize:       5,
			Verbose:            false,
		}
		
		authzhandler.Store, err = data.NewDataStore(TestOptions)
		ts, u := getAPIServerAndAccessInfo(http.StatusOK, validBody, "arc", "resourceid")
		defer ts.Close()

		response, err := u.CheckAccess(request)
		if err != nil {
			t.Errorf("Should not have gotten error: %s", err.Error())
		}
		if !response.Allowed || response.Denied)
			t.Errorf("Should have gotten access allowed. Got: Allowed:%t, Denied:%t", respresponse.Allowed, resresponse.Denied)
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
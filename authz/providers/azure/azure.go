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
package azure

import (
	"strings"

	"github.com/Azure/go-autorest/autorest/azure"
	auth "github.com/appscode/guard/auth/providers/azure"
	"github.com/appscode/guard/authz"
	"github.com/appscode/guard/authz/providers/azure/rbac"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	authzv1 "k8s.io/api/authorization/v1"
)

const (
	OrgType = "azure"
)

func init() {
	authz.SupportedOrgs = append(authz.SupportedOrgs, OrgType)
}

type Authorizer struct {
	auth.Options
	rbacClient *rbac.AccessInfo
}

type authzInfo struct {
	AADEndpoint string
	ARMEndPoint string
}

func New(opts auth.Options) (authz.Interface, error) {
	c := &Authorizer{
		Options: opts,
	}

	authzInfoVal, err := getAuthInfo(opts.Environment)
	if err != nil {
		return nil, errors.Wrap(err, "Error in getAuthInfo %s")
	}

	switch opts.AuthzMode {
	case auth.ARCAuthzMode:
		c.rbacClient = rbac.New(opts.ClientID, opts.ClientSecret, opts.TenantID, opts.UseGroupUID, authzInfoVal.AADEndpoint, authzInfoVal.ARMEndPoint, opts.AuthzMode, opts.ResourceId)
	case auth.AKSAuthzMode:
		c.rbacClient = rbac.NewWithAKS(opts.AKSAuthzURL, opts.TenantID, authzInfoVal.ARMEndPoint, opts.AuthzMode, opts.ResourceId)
	}
	return c, nil
}

func (s Authorizer) Check(request *authzv1.SubjectAccessReviewSpec) (*authzv1.SubjectAccessReviewStatus, error) {
	// check if user is service account
	if strings.Contains((*request).User, "system") {
		glog.V(3).Infof("returning no op to service accounts")
		return &authzv1.SubjectAccessReviewStatus{Allowed: false, Reason: "no opinion"}, nil
	}
	return s.rbacClient.CheckAccess(request)
}

func getAuthInfo(environment string) (*authzInfo, error) {
	var err error
	env := azure.PublicCloud
	if environment != "" {
		env, err = azure.EnvironmentFromName(environment)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse environment for azure")
		}
	}

	return &authzInfo{
		AADEndpoint: env.ActiveDirectoryEndpoint,
		ARMEndPoint: env.ResourceManagerEndpoint,
	}, nil
}

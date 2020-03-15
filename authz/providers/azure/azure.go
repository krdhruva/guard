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
	"fmt"
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
	Options
	rbacClient *rbac.AccessInfo
}

type authzInfo struct {
	AADEndpoint string
	ARMEndPoint string
}

func New(opts Options, authOpts auth.Options) (authz.Interface, error) {
	c := &Authorizer{
		Options: opts,
	}

	authzInfoVal, err := getAuthInfo(authOpts.Environment)
	if err != nil {
		fmt.Printf("error in getAuthInfo %s", err)
		return nil, err
	}

	switch opts.AuthzMode {
	case ARCAuthzMode:
		c.rbacClient, err = rbac.New(authOpts.ClientID, authOpts.ClientSecret, authOpts.TenantID, authOpts.UseGroupUID, authzInfoVal.AADEndpoint, authzInfoVal.ARMEndPoint, ARCAuthzMode, opts.ResourceId)
	case AKSAuthzMode:
		c.rbacClient, err = rbac.NewWithAKS(opts.AKSAuthzURL, authOpts.TenantID, authzInfoVal.ARMEndPoint, AKSAuthzMode, opts.ResourceId)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ms rbac client")
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

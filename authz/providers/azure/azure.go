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
	"errors"
	"context"

	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/appscode/guard/authz"
	"github.com/appscode/guard/authz/providers/azure/rbac"
	auth "github.com/appscode/guard/auth/providers/azure"
	authzv1 "k8s.io/api/authorization/v1"

	
)


const (
	OrgType            = "azure"	
)

func init() {
	authz.SupportedOrgs = append(authz.SupportedOrgs, OrgType)
}

type Authorizer struct {
	auth.Options
	rbacClient *rbac.AccessInfo
	ctx         context.Context
}

type authzInfo struct {
	AADEndpoint string
	MSRbacHost string
	Issuer      string	
}

func New(opts auth.Options) (authz.Interface, error) {
	c := &Authorizer{
		Options: opts,
		ctx:     context.Background(),
	}

	authzInfoVal, err := getAuthInfo(c.Environment, c.TenantID, auth.GetMetadata)
	if err != nil {
		return nil, err
	}

	glog.V(3).Infof("Using issuer url: %v", authzInfoVal.Issuer)
	
	switch opts.AuthzMode {
	case auth.ARCAuthzMode:
		c.rbacClient, err = rbac.New(c.ClientID, c.ClientSecret, c.TenantID, c.UseGroupUID, authzInfoVal.AADEndpoint, authzInfoVal.MSRbacHost, auth.ARCAuthzMode, opts.ResourceId)
	case auth.AKSAuthzMode:
		c.rbacClient, err = rbac.NewWithAKS(c.AKSTokenURL, c.TenantID, authzInfoVal.MSRbacHost, auth.AKSAuthzMode, opts.ResourceId)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ms rbac client")
	}
	return c, nil
}

func (s Authorizer) Check(request *authzv1.SubjectAccessReviewSpec) (*authzv1.SubjectAccessReviewStatus, error) {
	var resp authzv1.SubjectAccessReviewStatus
	// check if user is service account
	if (*request).UID != "" {
		resp.Allowed = false
		resp.Reason = "no opinion"
	}

	resp := s.rbacClient.CheckAccess(request)
	return resp, nil
}

func getAuthInfo(environment, tenantID string, getMetadata func(string, string) (*metadataJSON, error)) (*authzInfo, error) {
	var err error
	env := azure.PublicCloud
	if environment != "" {
		env, err = azure.EnvironmentFromName(environment)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse environment for azure")
		}
	}

	metadata, err := getMetadata(env.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata for azure")
	}

	return &authzInfo{
		AADEndpoint: env.ActiveDirectoryEndpoint,
		MSRbacHost: env.ResourceManagerEndpoint,
		Issuer:      metadata.Issuer,
	}, nil
}



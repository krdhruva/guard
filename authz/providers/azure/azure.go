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
	"context"
	"fmt"
	"strings"

	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/appscode/guard/authz"
	"github.com/appscode/guard/authz/providers/azure/rbac"
	"github.com/golang/glog"
	"github.com/pkg/errors"
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
	Options
	rbacClient *rbac.AccessInfo
	ctx         context.Context
}

type authzInfo struct {
	AADEndpoint string
	MSRbacHost string
	Issuer      string	
}

func New(opts Options, authOpts auth.Options) (authz.Interface, error) {
	c := &Authorizer{
		Options: opts,
		ctx:     context.Background(),
	}

	authzInfoVal, err := getAuthInfo(authOpts.Environment, authOpts.TenantID, auth.GetMetadata)
	if err != nil {
		fmt.Printf("error in getAuthInfo %s",err)
		return nil, err
	}

	fmt.Printf("getAuthInfo AADEndpoint:%s,rbachost:%s,issuer:%s",authzInfoVal.AADEndpoint, authzInfoVal.MSRbacHost,authzInfoVal.Issuer)
	glog.V(3).Infof("Using issuer url: %v", authzInfoVal.Issuer)
	
	switch opts.AuthzMode {
	case ARCAuthzMode:
		c.rbacClient, err = rbac.New(authOpts.ClientID, authOpts.ClientSecret, authOpts.TenantID, authOpts.UseGroupUID, authzInfoVal.AADEndpoint, authzInfoVal.MSRbacHost, ARCAuthzMode, opts.ResourceId)
	case AKSAuthzMode:
		c.rbacClient, err = rbac.NewWithAKS(authOpts.AKSTokenURL, authOpts.TenantID, authzInfoVal.MSRbacHost, AKSAuthzMode, opts.ResourceId)
	}
	if err != nil {
		fmt.Printf("failed to create rbac client %s",err)
		return nil, errors.Wrap(err, "failed to create ms rbac client")
	}

	if c.rbacClient == nil {
		fmt.Println("rbac client is nil in azure")
	}
	return c, nil
}

func (s Authorizer) Check(request *authzv1.SubjectAccessReviewSpec) (*authzv1.SubjectAccessReviewStatus, error) {
	// check if user is service account
	fmt.Printf("call is for UID:%s,user:%s",(*request).UID, (*request).User)
	if (*request).UID != "" || strings.Contains((*request).User,"system") {
		glog.V(3).Infof("returning no op to service accounts")
		fmt.Println("returning no op to sa")
		return &authzv1.SubjectAccessReviewStatus{Allowed: false, Reason: "no opinion"}, nil
	}
	fmt.Println("KD:returning resonse for user")
	if s.rbacClient == nil {
		fmt.Println("rbac client is nill")
	}

	response, _ := s.rbacClient.CheckAccess(request)
	if response == nil {
		fmt.Println("nil in checkaccess response")
	}

	return response, nil
}

func getAuthInfo(environment, tenantID string, getMetadata func(string, string) (*auth.MetadataJSON, error)) (*authzInfo, error) {
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



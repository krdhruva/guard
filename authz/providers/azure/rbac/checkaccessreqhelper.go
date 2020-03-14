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
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	authzv1 "k8s.io/api/authorization/v1"
)

type SubjectInfoAttributes struct {
	ObjectId              string   `json:"ObjectId"`
	Groups                []string `json:"Groups,omitempty"`
	ExpandGroupMembership bool     `json:"xms-pasrp-retrievegroupmemberships,omitempty"`
}

type SubjectInfo struct {
	Attributes SubjectInfoAttributes `json:"Attributes"`
}

type AuthorizationEntity struct {
	Id string `json:"Id"`
}

type AuthorizationActionInfo struct {
	AuthorizationEntity
	IsDataAction bool `json:"IsDataAction"`
}

type CheckAccessRequest struct {
	Subject  SubjectInfo               `json:"Subject"`
	Actions  []AuthorizationActionInfo `json:"Actions"`
	Resource AuthorizationEntity       `json:"Resource"`
}

type AccessDecesion struct {
	Decesion string `json:"accessDecision"`
}

type RoleAssignment struct {
	Id               string `json:"Id"`
	RoleDefinitionId string `json:"RoleDefinitionId"`
	PrincipalId      string `json:"PrincipalId"`
	PrincipalType    string `json:"PrincipalType"`
	Scope            string `json:"Scope"`
	Condition        string `json:"Condition"`
	ConditionVersion string `json:"ConditionVersion"`
	CanDelegate      bool   `json:"CanDelegate"`
}

type AzureRoleAssignment struct {
	DelegatedManagedIdentityResourceId string `json:"DelegatedManagedIdentityResourceId"`
	RoleAssignment
}

type Permission struct {
	Actions       []string `json:"actions,omitempty"`
	NoActions     []string `json:"noactions,omitempty"`
	DataActions   []string `json:"dataactions,omitempty"`
	NoDataActions []string `json:"nodataactions,omitempty"`
}

type Principal struct {
	Id   string `json:"Id"`
	Type string `json:"Type"`
}

type DenyAssignment struct {
	Id          string `json:"Id"`
	Name        string `json:"Name"`
	Description string `json:"Description"`
	Permission
	Scope                   string `json:"Scope"`
	DoNotApplyToChildScopes bool   `json:"DoNotApplyToChildScopes"`
	principals              []Principal
	excludeprincipals       []Principal
	Condition               string `json:"Condition"`
	ConditionVersion        string `json:"ConditionVersion"`
}
type AzureDenyAssignment struct {
	IsSystemProtected string `json:"IsSystemProtected"`
	DenyAssignment
}

type AuthorizationDecesion struct {
	Decesion            string              `json:"accessDecision"`
	ActionId            string              `json:"actionId"`
	IsDataAction        bool                `json:"isDataAction"`
	AzureRoleAssignment AzureRoleAssignment `json:"roleAssignment"`
	AzureDenyAssignment AzureDenyAssignment `json:"denyAssignment"`
	TimeToLiveInMs      int                 `json:"timeToLiveInMs"`
}

func getUserId(userName string) string {
	switch userName {
	case "krdhruva@microsoft.com":
		return "63e8a863-9ae9-4f3c-b0b7-fd9df05c712e"
	case "test@KDOrg.onmicrosoft.com":
		return "62103f2e-051d-48cc-af47-b1ff3deec630"
	default:
		return "62103f2e-051d-48cc-af47-b1ff3deec630"
	}
}

func getScope(resourceId string, attr *authzv1.ResourceAttributes) string {
	if attr != nil && attr.Namespace != "" {
		return resourceId + "/namespace/" + attr.Namespace
	}
	return resourceId
}

func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

func getSecGroups(groups []string) []string {
	var finalGroups []string
	for _, element := range groups {
		if IsValidUUID(element) {
			finalGroups = append(finalGroups, element)
		}
	}
	return finalGroups
}

func getActionName(verb string) string {
	switch verb {
	case "get":
		fallthrough
	case "list":
		fallthrough
	case "watch":
		return "read"
	case "create":
		return "action"
	case "update":
		return "write"
	case "delete":
		return "delete"
	default:
		return ""
	}
}

func getDataAction(subRevReq *authzv1.SubjectAccessReviewSpec, clusterType string) AuthorizationActionInfo {
	authInfo := AuthorizationActionInfo{
		IsDataAction: true}

	authInfo.AuthorizationEntity.Id = clusterType
	if subRevReq.ResourceAttributes != nil {
		if subRevReq.ResourceAttributes.Group != "" {
			authInfo.AuthorizationEntity.Id += "/" + subRevReq.ResourceAttributes.Group
		}
		authInfo.AuthorizationEntity.Id += "/" + subRevReq.ResourceAttributes.Resource + "/" + getActionName(subRevReq.ResourceAttributes.Verb)
	} else if subRevReq.NonResourceAttributes != nil {
		authInfo.AuthorizationEntity.Id += subRevReq.NonResourceAttributes.Path + "/" + getActionName(subRevReq.NonResourceAttributes.Verb)
	}
	return authInfo
}

func PrepareCheckAccessRequest(req *authzv1.SubjectAccessReviewSpec, clusterType, resourceId string) *CheckAccessRequest {
	checkaccessreq := CheckAccessRequest{}
	checkaccessreq.Subject.Attributes.ObjectId = getUserId(req.User)

	if req.Groups != nil && len(req.Groups) > 0 {
		groups := getSecGroups(req.Groups)
		if groups != nil && len(groups) > 0 {
			checkaccessreq.Subject.Attributes.Groups = groups
			checkaccessreq.Subject.Attributes.ExpandGroupMembership = true
		}
	}

	tmp := make([]AuthorizationActionInfo, 1)
	tmp[0] = getDataAction(req, clusterType)
	checkaccessreq.Actions = tmp
	checkaccessreq.Resource.Id = getScope(resourceId, req.ResourceAttributes)

	return &checkaccessreq
}

func getNameSpaceScope(req *authzv1.SubjectAccessReviewSpec, str *string) bool {
	if req.ResourceAttributes != nil && req.ResourceAttributes.Namespace != "" {
		*str = "/namespace/" + req.ResourceAttributes.Namespace
		return true
	}
	return false
}

func ConvertCheckAccessResponse(body []byte) (*authzv1.SubjectAccessReviewStatus, error) {
	var response []AuthorizationDecesion
	var allowed bool
	var denied bool
	var verdict string
	err := json.Unmarshal(body, &response)
	if err != nil {
		glog.V(10).Infoln("Failed to parse checkacccess response!")
		fmt.Printf("failed to parse checkaccess response!%s", err.Error())
		return nil, errors.Wrap(err, "Error in unmarshalling check access response.")
	}

	if response[0].Decesion == "Allowed" {
		allowed = true
		verdict = "allowed"
	} else {
		allowed = false
		denied = true
		verdict = "user does not have access to the resource"
	}

	return &authzv1.SubjectAccessReviewStatus{Allowed: allowed, Reason: verdict, Denied: denied}, nil
}

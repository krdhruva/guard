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
	decesion string `json:"accessDecision"`
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
	actions       []string `json:"actions,omitempty"`
	noactions     []string `json:"noactions,omitempty"`
	dataactions   []string `json:"dataactions,omitempty"`
	nodataactions []string `json:"nodataactions,omitempty"`
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
	decesion            string              `json:"accessDecision"`
	ActionId            string              `json:"actionId"`
	isDataAction        bool                `json:"isDataAction"`
	azureRoleAssignment AzureRoleAssignment `json:"roleAssignment"`
	azureDenyAssignment AzureDenyAssignment `json:"denyAssignment"`
	timeToLiveInMs      int                 `json:"timeToLiveInMs"`
}

func getUserId(userName string) string {
	return "63e8a863-9ae9-4f3c-b0b7-fd9df05c712e"
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
		return "read"
	case "put":
		return "write"
	case "delete":
		return "delete"
	case "post":
		return "action"
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
		fmt.Printf("/n Group:%s, Resource:%s, Verb:%s", subRevReq.ResourceAttributes.Group, subRevReq.ResourceAttributes.Resource, subRevReq.ResourceAttributes.Verb)
	} else if subRevReq.NonResourceAttributes != nil {
		authInfo.AuthorizationEntity.Id += subRevReq.NonResourceAttributes.Path + "/" + getActionName(subRevReq.NonResourceAttributes.Verb)
		fmt.Printf("/n Path:%s, Verb:%s", subRevReq.NonResourceAttributes.Path, subRevReq.NonResourceAttributes.Verb)
	}
	return authInfo
}

func PrepareCheckAccessRequest(req *authzv1.SubjectAccessReviewSpec, clusterType, resourceId string) *CheckAccessRequest {
	checkaccessreq := CheckAccessRequest{}
	checkaccessreq.Subject.Attributes.ObjectId = getUserId(req.User)

	if len(req.Groups) > 0 {
		groups := getSecGroups(req.Groups)
		if len(groups) > 0 {
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
		fmt.Printf("str:%s", str)
		return true
	}
	return false
}

func ConvertCheckAccessResponse(body []byte) *authzv1.SubjectAccessReviewStatus {
	var response []AuthorizationDecesion
	var allowed bool
	var denied bool
	var verdict string
	err := json.Unmarshal(body, &response)
	if err != nil {
		glog.V(10).Infoln("Failed to parse checkacccess response!")
		fmt.Printf("failed to parse checkaccess response!%s", err.Error())
	}

	if response[0].decesion == "Allowed" {
		allowed = true
	} else if response[0].decesion == "NotAllowed" {
		allowed = false
		verdict = "user does not have access to the resource"
	} else if response[0].decesion == "Denied" {
		allowed = false
		denied = true
		verdict = "user does not have access to the resource"
	}

	fmt.Printf("allowed is %d, denied is %d, reason %s", allowed, denied, verdict)

	return &authzv1.SubjectAccessReviewStatus{Allowed: allowed, Reason: verdict, Denied: denied}
}

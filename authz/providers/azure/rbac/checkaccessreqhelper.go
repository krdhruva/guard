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
	"net/http"
	"net/url"	
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	"github.com/appscode/guard/auth/providers/azure/graph"
	jsoniter "github.com/json-iterator/go"
)

type SubjectInfoAttributes struct {
	ObjectId string 					`json:"ObjectId"`
	Groups []string 					`json:"Groups"`
	ExpandGroupMembership bool			`json:"xms-pasrp-retrievegroupmemberships"`
}

type SubjectInfo struct {
	Attributes SubjectInfoAttributes	`json:"Attributes"`
}

type AuthorizationEntity struct {
	Id string `json:"Id"`
}

type AuthorizationActionInfo struct {
	AuthorizationEntity
	IsDataAction bool	`json:"IsDataAction"`
}

type CheckAccessRequest struct {
	Subject SubjectInfo 				`json:"Subject"`
	Actions []AuthorizationActionInfo	`json:"Actions"`   
	Resource AuthorizationEntity		`json:"Resource"`
}

type AccessDecesion struct {
	decesion string `json:"accessDecesion"`
}

type RoleAssignment struct {
	Id string `json:"Id"`
	RoleDefinitionId string `json:"RoleDefinitionId"`
	PrincipalId string `json:"PrincipalId"`
	PrincipalType string `json:"PrincipalType"`
	Scope string `json:"Scope"`
	Condition string `json:"Condition"`
	ConditionVersion string `json:"ConditionVersion"`
	CanDelegate bool `json:"CanDelegate"`
}

type AzureRoleAssignment struct {
	DelegatedManagedIdentityResourceId string `json:"DelegatedManagedIdentityResourceId"`
	RoleAssignment
}

type Permission struct {
	actions []string `json:"actions"`
	noactions []string `json:"noactions"`
	dataactions []string `json:"dataactions"`
	nodataactions []string `json:"nodataactions"`
}

type Principal struct {
	Id string `json:"Id"`
	Type string `json:"Type"`
}

type DenyAssignment struct {
	Id string `json:"Id"`
	Name string `json:"Name"`
	Description string `json:"Description"`
	Permission
	Scope string `json:"Scope"`
	DoNotApplyToChildScopes bool `json:"DoNotApplyToChildScopes"`
	principals Principals
	excludeprincipals ExcludePrincipals
	Condition string `json:"Condition"`
	ConditionVersion string `json:"ConditionVersion"`
}
type AzureDenyAssignment struct {
	IsSystemProtected string `json:"IsSystemProtected"`
	DenyAssignment
}

type AuthorizationDecesion struct {
	ActionId string `json:"ActionId"`
	AccessDecesion
	AzureRoleAssignment 
	AzureDenyAssignment 
}

func getUserId(userName string) string {	
	return "92634de3-03f6-4092-b41b-20616b11a464"
}

func getActionName(verb string) string {
	switch verb {
	case "get":
		return "read"
	case "put":
		return "write"
	case "delete":
		return "delete"
	case "post":
		return "action"
	}
}

func getDataAction(resourceAtt *authzv1.SubjectAccessReviewSpec.ResourceAttributes, clusterType string) AuthorizationActionInfo {
	var authInfo AuthorizationActionInfo
	authInfo.AuthorizationEntity.Id = MANAGED_CLUSTER + resourceAtt.Resource + getActionName(resourceAtt.verb)
	return authInfo
}

func PrepareCheckAccessRequest(req *authzv1.SubjectAccessReviewSpec, clusterType, resourceId string) (string, error) {
	var checkaccessreq CheckAccessRequest
	checkaccessreq.Subject.Attributes.ObjectId = getUserId(req.User)
	checkaccessreq.Subject.Attributes.Groups = req.Groups
	checkaccessreq.Subject.Attributes.ExpandGroupMembership = true

	if req.ResourceAttributes != nil {
		checkaccessreq.Actions[0] = getDataAction(req.ResourceAttributes, clusterType)
	}

	if req.NonResourceAttributes != nil {
		checkaccessreq.Actions[0] = getDataAction(req.NonResourceAttributes)
	}

	checkaccessreq.Resource.Id = resourceId

	bytes, err := json.Marshal(checkaccessreq)
	if err != nil {
		return "", err
	} else {
		return string(bytes), nil
	}
}

func getNameSpaceScoe(req *authzv1.SubjectAccessReviewSpec) string {
	if req.ResourceAttributes != nil && req.ResourceAttributes.Namespace != "" {
		return "/"+req.ResourceAttributes.Namespace
	}	
}

func ConvertCheckAccessResponse() *authzv1.SubjectAccessReviewStatus { 

}
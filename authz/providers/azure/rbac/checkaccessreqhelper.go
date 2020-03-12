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
	decesion string `json:"accessDecesion"`
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
	actions       []string `json:"actions"`
	noactions     []string `json:"noactions"`
	dataactions   []string `json:"dataactions"`
	nodataactions []string `json:"nodataactions"`
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
	default:
		return ""
	}
}

func getDataAction(subRevReq *authzv1.SubjectAccessReviewSpec, clusterType string) AuthorizationActionInfo {
	var authInfo AuthorizationActionInfo
	if subRevReq.ResourceAttributes != nil {
		fmt.Printf("incoming data: Group: %s, Res name: %s, namespace: %s, subres:%s, verb:%s", subRevReq.ResourceAttributes.Group, subRevReq.ResourceAttributes.Resource, subRevReq.ResourceAttributes.Namespace, subRevReq.ResourceAttributes.Verb)
		authInfo.AuthorizationEntity.Id = clusterType + subRevReq.ResourceAttributes.Group  +  "/" + subRevReq.ResourceAttributes.Resource + getActionName(subRevReq.ResourceAttributes.Verb)
		fmt.Printf("final string: %s", authInfo.AuthorizationEntity.Id)
	} else if subRevReq.NonResourceAttributes != nil {
		authInfo.AuthorizationEntity.Id = clusterType + subRevReq.NonResourceAttributes.Path + getActionName(subRevReq.NonResourceAttributes.Verb)
	}

	return authInfo
}

func PrepareCheckAccessRequest(req *authzv1.SubjectAccessReviewSpec, clusterType, resourceId string) ([]byte, error) {
	if req == nil {
		fmt.Println("KD: req nil")
	}

	var checkaccessreq CheckAccessRequest
	checkaccessreq.Subject.Attributes.ObjectId = getUserId(req.User)
	checkaccessreq.Subject.Attributes.Groups = req.Groups
	checkaccessreq.Subject.Attributes.ExpandGroupMembership = true
	tmp := make([]AuthorizationActionInfo, 1)
	tmp[0] = getDataAction(req, clusterType)
	checkaccessreq.Actions = tmp
	checkaccessreq.Resource.Id = resourceId

	fmt.Printf("checkaccess req: %s", checkaccessreq)
	fmt.Printf("User:%s, Groups:%s, Action:%s", req.User, req.Groups, getDataAction(req,clusterType))

	bytes, err := json.Marshal(checkaccessreq)
	if err != nil {
		fmt.Println("error in marshalling")
		fmt.Println(err)
		return nil, err
	} else {
		var jsonStr interface{}
		json.Unmarshal([]byte(bytes), &jsonStr)
		fmt.Println(jsonStr)
		return bytes, nil
	}
}

func getNameSpaceScoe(req *authzv1.SubjectAccessReviewSpec) *string {
	if req.ResourceAttributes != nil && req.ResourceAttributes.Namespace != "" {
		str := "/" + req.ResourceAttributes.Namespace
		// to-do this is wrong
		return &str
	}
	return nil
}

func ConvertCheckAccessResponse(body []byte) *authzv1.SubjectAccessReviewStatus {
	var response AuthorizationDecesion
	var allowed bool
	var denied bool
	var verdict string
	err := json.Unmarshal(body, &response)
	if err != nil {
		glog.V(10).Infoln("Failed to parse checkacccess response!")
		fmt.Printf("failed to parse checkaccess response!%s", err.Error())
	}

	if response.decesion == "Allowed" {
		allowed = true
	} else if response.decesion == "Not Allowed" {
		allowed = false
		verdict = "user does not have access to the resource"
	} else if response.decesion == "Denied" {
		allowed = false
		denied = true
		verdict = "user does not have access to the resource"
	}

	fmt.Printf("allowed is %d, denied is %d, reason %s", allowed, denied, verdict)

	return &authzv1.SubjectAccessReviewStatus{Allowed: allowed, Reason: verdict, Denied:denied}
}

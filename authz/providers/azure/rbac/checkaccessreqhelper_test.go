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
	"reflect"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
)

func Test_getScope(t *testing.T) {
	type args struct {
		resourceId string
		attr       *authzv1.ResourceAttributes
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"nilAttr", args{"resourceId", nil}, "resourceId"},
		{"bothnil", args{"", nil}, ""},
		{"emptyRes", args{"", &authzv1.ResourceAttributes{Namespace: ""}}, ""},
		{"emptyRes2", args{"", &authzv1.ResourceAttributes{Namespace: "test"}}, "/namespace/test"},
		{"emptyNS", args{"resourceId", &authzv1.ResourceAttributes{Namespace: ""}}, "resourceId"},
		{"bothPresent", args{"resourceId", &authzv1.ResourceAttributes{Namespace: "test"}}, "resourceId/namespace/test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getScope(tt.args.resourceId, tt.args.attr); got != tt.want {
				t.Errorf("getScope() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getSecGroups(t *testing.T) {
	type args struct {
		groups []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"nilGroup", args{nil}, nil},
		{"emptyGroup", args{[]string{}}, nil},
		{"noGuidGroup", args{[]string{"abc", "def", "system:ghi"}}, nil},
		{"someGroup",
			args{[]string{"abc", "1cffe3ae-93c0-4a87-9484-2e90e682aae9", "sys:admin", "", "0ab7f20f-8e9a-43ba-b5ac-1811c91b3d40"}},
			[]string{"1cffe3ae-93c0-4a87-9484-2e90e682aae9", "0ab7f20f-8e9a-43ba-b5ac-1811c91b3d40"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getSecGroups(tt.args.groups); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getSecGroups() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getDataAction(t *testing.T) {
	type args struct {
		subRevReq   *authzv1.SubjectAccessReviewSpec
		clusterType string
	}
	tests := []struct {
		name string
		args args
		want AuthorizationActionInfo
	}{
		{"aksAction", args{
			subRevReq: &authzv1.SubjectAccessReviewSpec{
				NonResourceAttributes: &authzv1.NonResourceAttributes{Path: "/apis", Verb: "list"}}, clusterType: "aks"},
			AuthorizationActionInfo{AuthorizationEntity: AuthorizationEntity{Id: "aks/apis/read"}, IsDataAction: true}},

		{"aksAction2", args{
			subRevReq: &authzv1.SubjectAccessReviewSpec{
				NonResourceAttributes: &authzv1.NonResourceAttributes{Path: "/logs", Verb: "update"}}, clusterType: "aks"},
			AuthorizationActionInfo{AuthorizationEntity: AuthorizationEntity{Id: "aks/logs/write"}, IsDataAction: true}},

		{"arc", args{
			subRevReq: &authzv1.SubjectAccessReviewSpec{
				ResourceAttributes: &authzv1.ResourceAttributes{Group: "", Resource: "pods", Verb: "delete"}}, clusterType: "arc"},
			AuthorizationActionInfo{AuthorizationEntity: AuthorizationEntity{Id: "arc/pods/delete"}, IsDataAction: true}},

		{"arc2", args{
			subRevReq: &authzv1.SubjectAccessReviewSpec{
				ResourceAttributes: &authzv1.ResourceAttributes{Group: "apps", Resource: "deployments", Verb: "create"}}, clusterType: "arc"},
			AuthorizationActionInfo{AuthorizationEntity: AuthorizationEntity{Id: "arc/apps/deployments/action"}, IsDataAction: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getDataAction(tt.args.subRevReq, tt.args.clusterType); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getDataAction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getNameSpaceScope(t *testing.T) {
	req := authzv1.SubjectAccessReviewSpec{ResourceAttributes: nil}
	str := ""
	want := false
	got := getNameSpaceScope(&req, &str)
	if got {
		t.Errorf("Want:%v, got:%v", want, got)
	}

	req = authzv1.SubjectAccessReviewSpec{
		ResourceAttributes: &authzv1.ResourceAttributes{Namespace: ""}}
	str = ""
	want = false
	got = getNameSpaceScope(&req, &str)
	if got {
		t.Errorf("Want:%v, got:%v", want, got)
	}

	req = authzv1.SubjectAccessReviewSpec{
		ResourceAttributes: &authzv1.ResourceAttributes{Namespace: "dev"}}
	str = ""
	outputstring := "/namespace/dev"
	want = true
	got = getNameSpaceScope(&req, &str)
	if !got || str != outputstring {
		t.Errorf("Want:%v - %s, got: %v - %s", want, outputstring, got, str)
	}
}

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
package authz

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/golang/glog"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/util/homedir"
)

var DefaultDataDir = func() string {
	if v, ok := os.LookupEnv("GUARD_DATA_DIR"); ok {
		glog.Infof("Using data dir %s found in GUARD_DATA_DIR env variable", v)
		return v
	}
	return filepath.Join(homedir.HomeDir(), ".guard")
}()

type orgs []string

var SupportedOrgs orgs

func (o orgs) Has(name string) bool {
	name = strings.TrimSpace(strings.ToLower(name))
	for _, org := range o {
		if org == name {
			return true
		}
	}
	return false
}

func (o orgs) String() string {
	names := make([]string, len(o))
	for i, org := range o {
		names[i] = strings.Title(org)
	}
	sort.Strings(names)
	return strings.Join(names, "/")
}

type Interface interface {
	Check(request *authzv1.SubjectAccessReviewSpec) (*authzv1.SubjectAccessReviewStatus, error)
}

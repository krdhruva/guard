module github.com/krdhruva/guard/authz/providers/azure

go 1.13

require (
	github.com/Azure/go-autorest v12.2.0+incompatible
	github.com/Azure/go-autorest/autorest v0.9.0
	github.com/appscode/guard v0.5.0-rc.1
	github.com/appscode/guard/authz v0.0.0-00010101000000-000000000000
	github.com/appscode/guard/authz/providers/azure/data v0.0.0-00010101000000-000000000000
	github.com/appscode/guard/authz/providers/azure/rbac v0.0.0-00010101000000-000000000000
	github.com/appscode/pat v0.0.0-20170521084856-48ff78925b79
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/google/uuid v1.1.1
	github.com/moul/http2curl v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.4.0
	k8s.io/api v0.18.1
	k8s.io/apimachinery v0.18.1
)

replace (
	github.com/appscode/guard/authz => ./../../../authz
	github.com/appscode/guard/authz/providers/azure/data => ./data
	github.com/appscode/guard/authz/providers/azure/rbac => ./rbac
)
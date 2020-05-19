module github.com/appscode/guard/authz/providers/azure/rbac

go 1.13

require (
	github.com/allegro/bigcache v1.2.1 // indirect
	github.com/appscode/guard v0.5.0
	github.com/appscode/guard/authz v0.0.0-00010101000000-000000000000
	github.com/appscode/guard/authz/providers/azure/data v0.0.0-00010101000000-000000000000
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/google/uuid v1.1.1
	github.com/moul/http2curl v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.5.1
	k8s.io/api v0.18.2
)

replace (
	github.com/appscode/guard/authz => ../../../../authz
	github.com/appscode/guard/authz/providers/azure/data => ../data
)

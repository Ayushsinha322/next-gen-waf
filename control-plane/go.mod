module github.com/your-org/sentinel-waf/control-plane

go 1.22

require (
	google.golang.org/grpc v1.66.0
	google.golang.org/protobuf v1.34.2
	github.com/spf13/cobra v1.8.1
	github.com/spf13/viper v1.19.0
	go.uber.org/zap v1.27.0
	github.com/gin-gonic/gin v1.10.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/hashicorp/raft v1.7.0
	github.com/hashicorp/memberlist v0.5.1
	go.etcd.io/bbolt v1.3.10
	github.com/prometheus/client_golang v1.20.0
	go.opentelemetry.io/otel v1.28.0
	github.com/stretchr/testify v1.9.0
)

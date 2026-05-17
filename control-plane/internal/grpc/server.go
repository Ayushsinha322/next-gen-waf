package grpc

import (
	"fmt"
	"net"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/pkg/proto/sentinelv1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

// Server wraps a gRPC server with auth interceptors and the ConfigService.
type Server struct {
	grpcServer   *grpc.Server
	configSvc    *ConfigServiceImpl
	log          *zap.Logger
	listenAddr   string
	tlsCfg       *TLSConfig
	jwt          *auth.JWTService
}

// TLSConfig holds certificate paths for mTLS.
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string // for mTLS; empty = no client cert required
}

// NewServer creates a new gRPC server with JWT auth interceptors.
func NewServer(listenAddr string, tlsCfg *TLSConfig, jwt *auth.JWTService, log *zap.Logger) (*Server, error) {
	configSvc := NewConfigService(log)

	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(auth.UnaryServerInterceptor(jwt)),
		grpc.StreamInterceptor(auth.StreamServerInterceptor(jwt)),
	}

	if tlsCfg != nil && tlsCfg.CertFile != "" {
		creds, err := credentials.NewServerTLSFromFile(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("grpc: loading TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	grpcServer := grpc.NewServer(opts...)
	sentinelv1.RegisterConfigServiceServer(grpcServer, configSvc)

	// Enable server reflection for debugging (grpcurl, etc.).
	reflection.Register(grpcServer)

	return &Server{
		grpcServer: grpcServer,
		configSvc:  configSvc,
		log:        log,
		listenAddr: listenAddr,
		tlsCfg:     tlsCfg,
		jwt:        jwt,
	}, nil
}

// ConfigService returns the ConfigServiceImpl for external updates.
func (s *Server) ConfigService() *ConfigServiceImpl {
	return s.configSvc
}

// Start begins listening and serving gRPC requests.  Blocks until the server
// stops.  Run it in a goroutine.
func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("grpc: listen on %s: %w", s.listenAddr, err)
	}

	s.log.Info("gRPC server listening",
		zap.String("addr", s.listenAddr),
		zap.Bool("tls", s.tlsCfg != nil && s.tlsCfg.CertFile != ""))

	return s.grpcServer.Serve(lis)
}

// Stop gracefully shuts down the gRPC server.
func (s *Server) Stop() {
	s.log.Info("gRPC server shutting down")
	s.grpcServer.GracefulStop()
}

// Package grpc provides the gRPC server for the Sentinel control plane,
// implementing ConfigService for data-plane node communication.
package grpc

import (
	"context"
	"sync"

	"github.com/your-org/sentinel-waf/control-plane/pkg/proto/sentinelv1"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ConfigServiceImpl implements sentinelv1.ConfigServiceServer.
type ConfigServiceImpl struct {
	sentinelv1.UnimplementedConfigServiceServer

	log         *zap.Logger
	mu          sync.RWMutex
	bundle      *sentinelv1.ConfigBundle
	revision    string
	subscribers map[string]chan *sentinelv1.ConfigBundle // nodeID → push channel
}

// NewConfigService creates a new ConfigService implementation.
func NewConfigService(log *zap.Logger) *ConfigServiceImpl {
	return &ConfigServiceImpl{
		log:         log,
		revision:    "0",
		subscribers: make(map[string]chan *sentinelv1.ConfigBundle),
	}
}

// UpdateBundle stores a new config bundle and pushes it to all active
// subscribers.  Call this when rules/sites/plugins change.
func (s *ConfigServiceImpl) UpdateBundle(bundle *sentinelv1.ConfigBundle) {
	s.mu.Lock()
	s.bundle = bundle
	s.revision = bundle.Revision
	// Push to all subscribers.
	for nodeID, ch := range s.subscribers {
		select {
		case ch <- bundle:
		default:
			s.log.Warn("subscriber channel full, dropping push",
				zap.String("node_id", nodeID))
		}
	}
	s.mu.Unlock()
	s.log.Info("config bundle updated", zap.String("revision", bundle.Revision))
}

// GetBundle returns the current config bundle for bootstrapping nodes.
func (s *ConfigServiceImpl) GetBundle(ctx context.Context, req *sentinelv1.GetBundleRequest) (*sentinelv1.ConfigBundle, error) {
	if req.NodeId == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}

	s.mu.RLock()
	bundle := s.bundle
	s.mu.RUnlock()

	if bundle == nil {
		return &sentinelv1.ConfigBundle{Revision: s.revision}, nil
	}

	s.log.Info("GetBundle", zap.String("node_id", req.NodeId))
	return bundle, nil
}

// Subscribe registers a data-plane node for streaming config updates.
func (s *ConfigServiceImpl) Subscribe(req *sentinelv1.SubscribeRequest, stream sentinelv1.ConfigService_SubscribeServer) error {
	if req.NodeId == "" {
		return status.Error(codes.InvalidArgument, "node_id is required")
	}

	ch := make(chan *sentinelv1.ConfigBundle, 8)

	s.mu.Lock()
	// Close any existing subscription for this node (reconnect).
	if old, ok := s.subscribers[req.NodeId]; ok {
		close(old)
	}
	s.subscribers[req.NodeId] = ch
	s.mu.Unlock()

	s.log.Info("node subscribed",
		zap.String("node_id", req.NodeId),
		zap.Strings("capabilities", req.Capabilities))

	defer func() {
		s.mu.Lock()
		delete(s.subscribers, req.NodeId)
		close(ch)
		s.mu.Unlock()
		s.log.Info("node unsubscribed", zap.String("node_id", req.NodeId))
	}()

	// Send current bundle immediately.
	s.mu.RLock()
	if s.bundle != nil {
		if err := stream.Send(s.bundle); err != nil {
			s.mu.RUnlock()
			return err
		}
	}
	s.mu.RUnlock()

	// Stream future updates.
	for {
		select {
		case bundle, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(bundle); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// ReportStatus receives streaming status updates from data-plane nodes.
func (s *ConfigServiceImpl) ReportStatus(stream sentinelv1.ConfigService_ReportStatusServer) error {
	for {
		status, err := stream.Recv()
		if err != nil {
			return err
		}
		s.log.Debug("node status",
			zap.String("node_id", status.NodeId),
			zap.Uint64("rps", status.RequestsPerSec),
			zap.Uint64("blocked_per_sec", status.BlockedPerSec),
			zap.Float64("cpu_pct", status.CpuPct),
			zap.Float64("mem_pct", status.MemPct),
			zap.String("config_revision", status.ConfigRevision),
		)
	}
}

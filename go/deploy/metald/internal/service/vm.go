package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/unkeyed/unkey/go/deploy/metald/internal/backend/types"
	"github.com/unkeyed/unkey/go/deploy/metald/internal/billing"
	"github.com/unkeyed/unkey/go/deploy/metald/internal/database"
	"github.com/unkeyed/unkey/go/deploy/metald/internal/observability"
	metaldv1 "github.com/unkeyed/unkey/go/gen/proto/metal/vmprovisioner/v1"
	"github.com/unkeyed/unkey/go/gen/proto/metal/vmprovisioner/v1/vmprovisionerv1connect"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace"
)

// VMService implements the VmServiceHandler interface
type VMService struct {
	backend          types.Backend
	logger           *slog.Logger
	metricsCollector *billing.MetricsCollector
	vmMetrics        *observability.VMMetrics
	vmRepo           *database.VMRepository
	tracer           trace.Tracer
	vmprovisionerv1connect.UnimplementedVmServiceHandler
}

// NewVMService creates a new VM service instance
func NewVMService(backend types.Backend, logger *slog.Logger, metricsCollector *billing.MetricsCollector, vmMetrics *observability.VMMetrics, vmRepo *database.VMRepository) *VMService {
	tracer := otel.Tracer("metald.service.vm")
	return &VMService{ //nolint:exhaustruct // UnimplementedVmServiceHandler is embedded and provides default implementations
		backend:          backend,
		logger:           logger.With("service", "vm"),
		metricsCollector: metricsCollector,
		vmMetrics:        vmMetrics,
		vmRepo:           vmRepo,
		tracer:           tracer,
	}
}

// CreateVm creates a new VM instance
func (s *VMService) CreateVm(ctx context.Context, req *connect.Request[metaldv1.CreateVmRequest]) (*connect.Response[metaldv1.CreateVmResponse], error) {
	ctx, span := s.tracer.Start(ctx, "metald.vm.create",
		trace.WithAttributes(
			attribute.String("service.name", "metald"),
			attribute.String("operation.name", "create_vm"),
		),
	)
	defer span.End()

	s.logger.LogAttrs(ctx, slog.LevelInfo, "creating vm",
		slog.String("method", "CreateVm"),
	)

	// Record VM create request metric
	if s.vmMetrics != nil {
		s.vmMetrics.RecordVMCreateRequest(ctx, s.getBackendType())
	}

	config := req.Msg.GetConfig()

	// DEBUG: Log full request config for debugging
	if config != nil {
		configJSON, _ := json.Marshal(config)
		s.logger.LogAttrs(ctx, slog.LevelDebug, "full VM config received",
			slog.String("config_json", string(configJSON)),
		)
	}
	if config == nil {
		err := fmt.Errorf("vm config is required")
		span.RecordError(err)
		s.logger.LogAttrs(ctx, slog.LevelError, "missing vm config")
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMCreateFailure(ctx, s.getBackendType(), "missing_config")
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Extract authenticated customer ID from context
	userID, err := ExtractUserID(ctx)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "missing authenticated customer context")
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMCreateFailure(ctx, s.getBackendType(), "missing_customer_context")
		}
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("customer authentication required"))
	}

	// Validate that request customer_id matches authenticated customer (if provided)
	if req.Msg.GetUserId() != "" && req.Msg.GetUserId() != userID {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "SECURITY: user_id mismatch in request",
			slog.String("authenticated_customer", userID),
			slog.String("request_customer", req.Msg.GetTenantId()),
		)
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("user_id mismatch"))
	}

	// Validate required fields
	if validateErr := s.validateVMConfig(config); validateErr != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "invalid vm config",
			slog.String("error", validateErr.Error()),
		)
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMCreateFailure(ctx, s.getBackendType(), "invalid_config")
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, validateErr)
	}

	// Add tenant context to logs for audit trail
	s.logWithTenantContext(ctx, slog.LevelInfo, "creating vm",
		slog.Int("vcpus", int(config.GetCpu().GetVcpuCount())),
		slog.Int64("memory_bytes", config.GetMemory().GetSizeBytes()),
	)

	// Create VM using backend (config is already in unified format)
	start := time.Now()
	vmID, err := s.backend.CreateVM(ctx, config)
	duration := time.Since(start)
	if err != nil {
		span.RecordError(err)
		span.SetAttributes(
			attribute.String("error.type", "backend_error"),
			attribute.String("error.message", err.Error()),
		)
		s.logWithTenantContext(ctx, slog.LevelError, "failed to create vm",
			slog.String("error", err.Error()),
		)
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMCreateFailure(ctx, s.getBackendType(), "backend_error")
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create vm: %w", err))
	}

	// Persist VM to database - critical for state consistency
	if err := s.vmRepo.CreateVMWithContext(ctx, vmID, userID, config, metaldv1.VmState_VM_STATE_CREATED); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to persist vm to database",
			slog.String("vm_id", vmID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)

		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMCreateFailure(ctx, s.getBackendType(), "database_error")
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to persist vm: %w", err))
	}

	// Record success attributes
	span.SetAttributes(
		attribute.String("vm_id", vmID),
		attribute.String("user_id", userID),
		attribute.Int64("duration_ms", duration.Milliseconds()),
		attribute.Bool("success", true),
	)

	s.logger.LogAttrs(ctx, slog.LevelInfo, "vm created successfully",
		slog.String("vm_id", vmID),
		slog.Duration("duration", duration),
	)

	// Record successful VM creation
	if s.vmMetrics != nil {
		s.vmMetrics.RecordVMCreateSuccess(ctx, vmID, s.getBackendType(), duration)
	}

	return connect.NewResponse(&metaldv1.CreateVmResponse{
		VmId:  vmID,
		State: metaldv1.VmState_VM_STATE_CREATED,
	}), nil
}

// DeleteVm deletes a VM instance
func (s *VMService) DeleteVm(ctx context.Context, req *connect.Request[metaldv1.DeleteVmRequest]) (*connect.Response[metaldv1.DeleteVmResponse], error) {
	vmID := req.Msg.GetVmId()

	s.logger.LogAttrs(ctx, slog.LevelInfo, "deleting vm",
		slog.String("method", "DeleteVm"),
		slog.String("vm_id", vmID),
	)

	// Record VM delete request metric
	if s.vmMetrics != nil {
		s.vmMetrics.RecordVMDeleteRequest(ctx, vmID, s.getBackendType())
	}

	if vmID == "" {
		s.logger.LogAttrs(ctx, slog.LevelError, "missing vm id")
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMDeleteFailure(ctx, "", s.getBackendType(), "missing_vm_id")
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vm_id is required"))
	}

	// AIDEV-NOTE: Metrics collection re-enabled - metald now reads from Firecracker stats sockets
	// Stop metrics collection before deletion
	if s.metricsCollector != nil {
		s.metricsCollector.StopCollection(vmID)
		s.logger.LogAttrs(ctx, slog.LevelInfo, "stopped metrics collection",
			slog.String("vm_id", vmID),
		)
	}

	start := time.Now()
	err := s.backend.DeleteVM(ctx, vmID)
	duration := time.Since(start)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to delete vm",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMDeleteFailure(ctx, vmID, s.getBackendType(), "backend_error")
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to delete vm: %w", err))
	}

	// Soft delete VM in database - required for state consistency
	if err := s.vmRepo.DeleteVMWithContext(ctx, vmID); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to delete vm from database",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)

		// Database state consistency is critical - record as partial failure
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMDeleteFailure(ctx, vmID, s.getBackendType(), "database_error")
		}

		// Log warning about state inconsistency but don't fail the operation
		// since backend deletion was successful
		s.logger.LogAttrs(ctx, slog.LevelWarn, "vm delete succeeded in backend but failed in database - state inconsistency detected",
			slog.String("vm_id", vmID),
			slog.String("backend_status", "deleted"),
			slog.String("database_status", "active"),
			slog.String("action_required", "manual_database_cleanup"),
		)
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "vm deleted successfully",
		slog.String("vm_id", vmID),
		slog.Duration("duration", duration),
	)

	// Record successful VM deletion
	if s.vmMetrics != nil {
		s.vmMetrics.RecordVMDeleteSuccess(ctx, vmID, s.getBackendType(), duration)
	}

	return connect.NewResponse(&metaldv1.DeleteVmResponse{
		Success: true,
	}), nil
}

// BootVm boots a VM instance
func (s *VMService) BootVm(ctx context.Context, req *connect.Request[metaldv1.BootVmRequest]) (*connect.Response[metaldv1.BootVmResponse], error) {
	vmID := req.Msg.GetVmId()

	ctx, span := s.tracer.Start(ctx, "metald.vm.boot",
		trace.WithAttributes(
			attribute.String("service.name", "metald"),
			attribute.String("operation.name", "boot_vm"),
			attribute.String("vm_id", vmID),
		),
	)
	defer span.End()

	s.logger.LogAttrs(ctx, slog.LevelInfo, "booting vm",
		slog.String("method", "BootVm"),
		slog.String("vm_id", vmID),
	)

	// Record VM boot request metric
	if s.vmMetrics != nil {
		s.vmMetrics.RecordVMBootRequest(ctx, vmID, s.getBackendType())
	}

	if vmID == "" {
		s.logger.LogAttrs(ctx, slog.LevelError, "missing vm id")
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMBootFailure(ctx, "", s.getBackendType(), "missing_vm_id")
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vm_id is required"))
	}

	start := time.Now()
	err := s.backend.BootVM(ctx, vmID)
	duration := time.Since(start)
	if err != nil {
		span.RecordError(err)
		span.SetAttributes(
			attribute.String("error.type", "backend_error"),
			attribute.String("error.message", err.Error()),
		)
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to boot vm",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMBootFailure(ctx, vmID, s.getBackendType(), "backend_error")
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to boot vm: %w", err))
	}

	// Update VM state in database - required for state consistency
	if err := s.vmRepo.UpdateVMStateWithContext(ctx, vmID, metaldv1.VmState_VM_STATE_RUNNING, nil); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to update vm state in database",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)

		// Log warning about state inconsistency
		s.logger.LogAttrs(ctx, slog.LevelWarn, "vm boot succeeded in backend but state update failed in database - state inconsistency detected",
			slog.String("vm_id", vmID),
			slog.String("backend_status", "running"),
			slog.String("database_status", "unknown"),
			slog.String("action_required", "manual_state_sync"),
		)
	}

	// Record success attributes
	span.SetAttributes(
		attribute.String("vm_id", vmID),
		attribute.Int64("duration_ms", duration.Milliseconds()),
		attribute.Bool("success", true),
	)

	s.logger.LogAttrs(ctx, slog.LevelInfo, "vm booted successfully",
		slog.String("vm_id", vmID),
		slog.Duration("duration", duration),
	)

	// Record successful VM boot
	if s.vmMetrics != nil {
		s.vmMetrics.RecordVMBootSuccess(ctx, vmID, s.getBackendType(), duration)
	}

	return connect.NewResponse(&metaldv1.BootVmResponse{
		Success: true,
		State:   metaldv1.VmState_VM_STATE_RUNNING,
	}), nil
}

// ShutdownVm shuts down a VM instance
func (s *VMService) ShutdownVm(ctx context.Context, req *connect.Request[metaldv1.ShutdownVmRequest]) (*connect.Response[metaldv1.ShutdownVmResponse], error) {
	vmID := req.Msg.GetVmId()

	force := req.Msg.GetForce()
	timeout := req.Msg.GetTimeoutSeconds()

	s.logger.LogAttrs(ctx, slog.LevelInfo, "shutting down vm",
		slog.String("method", "ShutdownVm"),
		slog.String("vm_id", vmID),
		slog.Bool("force", force),
		slog.Int("timeout_seconds", int(timeout)),
	)

	// Record VM shutdown request metric
	if s.vmMetrics != nil {
		s.vmMetrics.RecordVMShutdownRequest(ctx, vmID, s.getBackendType(), force)
	}

	if vmID == "" {
		s.logger.LogAttrs(ctx, slog.LevelError, "missing vm id")
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMShutdownFailure(ctx, "", s.getBackendType(), force, "missing_vm_id")
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vm_id is required"))
	}

	// AIDEV-NOTE: Metrics collection re-enabled - metald now reads from Firecracker stats sockets
	// Stop metrics collection before shutdown
	if s.metricsCollector != nil {
		s.metricsCollector.StopCollection(vmID)
		s.logger.LogAttrs(ctx, slog.LevelInfo, "stopped metrics collection",
			slog.String("vm_id", vmID),
		)
	}

	start := time.Now()
	err := s.backend.ShutdownVMWithOptions(ctx, vmID, force, timeout)
	duration := time.Since(start)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to shutdown vm",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		if s.vmMetrics != nil {
			s.vmMetrics.RecordVMShutdownFailure(ctx, vmID, s.getBackendType(), force, "backend_error")
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to shutdown vm: %w", err))
	}

	// Update VM state in database - required for state consistency
	if err := s.vmRepo.UpdateVMStateWithContext(ctx, vmID, metaldv1.VmState_VM_STATE_SHUTDOWN, nil); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to update vm state in database",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)

		// Log warning about state inconsistency
		s.logger.LogAttrs(ctx, slog.LevelWarn, "vm shutdown succeeded in backend but state update failed in database - state inconsistency detected",
			slog.String("vm_id", vmID),
			slog.String("backend_status", "shutdown"),
			slog.String("database_status", "unknown"),
			slog.String("action_required", "manual_state_sync"),
		)
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "vm shutdown successfully",
		slog.String("vm_id", vmID),
		slog.Duration("duration", duration),
	)

	// Record successful VM shutdown
	if s.vmMetrics != nil {
		s.vmMetrics.RecordVMShutdownSuccess(ctx, vmID, s.getBackendType(), force, duration)
	}

	return connect.NewResponse(&metaldv1.ShutdownVmResponse{
		Success: true,
		State:   metaldv1.VmState_VM_STATE_SHUTDOWN,
	}), nil
}

// PauseVm pauses a VM instance
func (s *VMService) PauseVm(ctx context.Context, req *connect.Request[metaldv1.PauseVmRequest]) (*connect.Response[metaldv1.PauseVmResponse], error) {
	vmID := req.Msg.GetVmId()

	s.logger.LogAttrs(ctx, slog.LevelInfo, "pausing vm",
		slog.String("method", "PauseVm"),
		slog.String("vm_id", vmID),
	)

	if vmID == "" {
		s.logger.LogAttrs(ctx, slog.LevelError, "missing vm id")
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vm_id is required"))
	}

	if err := s.backend.PauseVM(ctx, vmID); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to pause vm",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to pause vm: %w", err))
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "vm paused successfully",
		slog.String("vm_id", vmID),
	)

	return connect.NewResponse(&metaldv1.PauseVmResponse{
		Success: true,
		State:   metaldv1.VmState_VM_STATE_PAUSED,
	}), nil
}

// ResumeVm resumes a paused VM instance
func (s *VMService) ResumeVm(ctx context.Context, req *connect.Request[metaldv1.ResumeVmRequest]) (*connect.Response[metaldv1.ResumeVmResponse], error) {
	vmID := req.Msg.GetVmId()

	s.logger.LogAttrs(ctx, slog.LevelInfo, "resuming vm",
		slog.String("method", "ResumeVm"),
		slog.String("vm_id", vmID),
	)

	if vmID == "" {
		s.logger.LogAttrs(ctx, slog.LevelError, "missing vm id")
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vm_id is required"))
	}

	if err := s.backend.ResumeVM(ctx, vmID); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to resume vm",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to resume vm: %w", err))
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "vm resumed successfully",
		slog.String("vm_id", vmID),
	)

	return connect.NewResponse(&metaldv1.ResumeVmResponse{
		Success: true,
		State:   metaldv1.VmState_VM_STATE_RUNNING,
	}), nil
}

// RebootVm reboots a VM instance
func (s *VMService) RebootVm(ctx context.Context, req *connect.Request[metaldv1.RebootVmRequest]) (*connect.Response[metaldv1.RebootVmResponse], error) {
	vmID := req.Msg.GetVmId()

	s.logger.LogAttrs(ctx, slog.LevelInfo, "rebooting vm",
		slog.String("method", "RebootVm"),
		slog.String("vm_id", vmID),
	)

	if vmID == "" {
		s.logger.LogAttrs(ctx, slog.LevelError, "missing vm id")
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vm_id is required"))
	}

	if err := s.backend.RebootVM(ctx, vmID); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to reboot vm",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to reboot vm: %w", err))
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "vm rebooted successfully",
		slog.String("vm_id", vmID),
	)

	return connect.NewResponse(&metaldv1.RebootVmResponse{
		Success: true,
		State:   metaldv1.VmState_VM_STATE_RUNNING,
	}), nil
}

// GetVmInfo gets VM information
func (s *VMService) GetVmInfo(ctx context.Context, req *connect.Request[metaldv1.GetVmInfoRequest]) (*connect.Response[metaldv1.GetVmInfoResponse], error) {
	vmID := req.Msg.GetVmId()

	s.logger.LogAttrs(ctx, slog.LevelInfo, "getting vm info",
		slog.String("method", "GetVmInfo"),
		slog.String("vm_id", vmID),
	)

	// Record VM info request metric
	if s.vmMetrics != nil {
		s.vmMetrics.RecordVMInfoRequest(ctx, vmID, s.getBackendType())
	}

	if vmID == "" {
		s.logger.LogAttrs(ctx, slog.LevelError, "missing vm id")
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vm_id is required"))
	}

	info, err := s.backend.GetVMInfo(ctx, vmID)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to get vm info",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get vm info: %w", err))
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "retrieved vm info successfully",
		slog.String("vm_id", vmID),
		slog.String("state", info.State.String()),
	)

	return connect.NewResponse(&metaldv1.GetVmInfoResponse{ //nolint:exhaustruct // Metrics and BackendInfo fields are optional and not populated in this response
		VmId:        vmID,
		Config:      info.Config,
		State:       info.State,
		NetworkInfo: info.NetworkInfo,
	}), nil
}

// ListVms lists all VMs managed by this service for the authenticated customer
func (s *VMService) ListVms(ctx context.Context, req *connect.Request[metaldv1.ListVmsRequest]) (*connect.Response[metaldv1.ListVmsResponse], error) {
	s.logger.LogAttrs(ctx, slog.LevelInfo, "listing vms",
		slog.String("method", "ListVms"),
	)

	// Record VM list request metric
	if s.vmMetrics != nil {
		s.vmMetrics.RecordVMListRequest(ctx, s.getBackendType())
	}

	// Extract authenticated customer ID for filtering
	userID, err := ExtractUserID(ctx)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "missing authenticated customer context")
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("customer authentication required"))
	}

	// Get VMs from database filtered by customer
	dbVMs, err := s.vmRepo.ListVMsByCustomerWithContext(ctx, userID)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to list vms from database",
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list vms: %w", err))
	}

	var vms []*metaldv1.VmInfo
	// Check for overflow before conversion
	if len(dbVMs) > math.MaxInt32 {
		s.logger.LogAttrs(ctx, slog.LevelError, "too many VMs to list",
			slog.Int("count", len(dbVMs)),
		)
		return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("too many VMs to list: %d", len(dbVMs)))
	}
	totalCount := int32(len(dbVMs)) //nolint:gosec // Overflow check performed above

	// Convert database VMs to protobuf format
	for _, vm := range dbVMs {
		vmInfo := &metaldv1.VmInfo{ //nolint:exhaustruct // Optional fields are populated conditionally below based on available data
			VmId:       vm.ID,
			State:      vm.State,
			CustomerId: vm.CustomerID,
		}

		// Add CPU and memory info if available
		if vm.ParsedConfig != nil {
			if vm.ParsedConfig.GetCpu() != nil {
				vmInfo.VcpuCount = vm.ParsedConfig.GetCpu().GetVcpuCount()
			}
			if vm.ParsedConfig.GetMemory() != nil {
				vmInfo.MemorySizeBytes = vm.ParsedConfig.GetMemory().GetSizeBytes()
			}
			if vm.ParsedConfig.GetMetadata() != nil {
				vmInfo.Metadata = vm.ParsedConfig.GetMetadata()
			}
		}

		// Set timestamps from database
		vmInfo.CreatedTimestamp = vm.CreatedAt.Unix()
		vmInfo.ModifiedTimestamp = vm.UpdatedAt.Unix()

		vms = append(vms, vmInfo)
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "vm listing completed",
		slog.Int("count", int(totalCount)),
	)

	return connect.NewResponse(&metaldv1.ListVmsResponse{ //nolint:exhaustruct // NextPageToken field not used as pagination is not implemented yet
		Vms:        vms,
		TotalCount: totalCount,
	}), nil
}

// validateVMConfig validates the VM configuration
func (s *VMService) validateVMConfig(config *metaldv1.VmConfig) error {
	// AIDEV-BUSINESS_RULE: VM configuration must have CPU, memory, and boot settings
	if config.GetCpu() == nil {
		return fmt.Errorf("cpu configuration is required")
	}

	if config.GetMemory() == nil {
		return fmt.Errorf("memory configuration is required")
	}

	if config.GetBoot() == nil {
		return fmt.Errorf("boot configuration is required")
	}

	// Validate CPU configuration
	cpu := config.GetCpu()
	if cpu.GetVcpuCount() <= 0 {
		return fmt.Errorf("vcpu_count must be greater than 0")
	}

	if cpu.GetMaxVcpuCount() > 0 && cpu.GetMaxVcpuCount() < cpu.GetVcpuCount() {
		return fmt.Errorf("max_vcpu_count must be greater than or equal to vcpu_count")
	}

	// Validate memory configuration
	memory := config.GetMemory()
	if memory.GetSizeBytes() <= 0 {
		return fmt.Errorf("memory size_bytes must be greater than 0")
	}

	// Validate boot configuration
	boot := config.GetBoot()
	if boot.GetKernelPath() == "" {
		return fmt.Errorf("kernel_path is required")
	}

	// Validate storage configuration - ensure at least one storage device exists
	if len(config.GetStorage()) == 0 {
		return fmt.Errorf("at least one storage device is required")
	}

	// Validate that we have a root device
	hasRootDevice := false
	for i, storage := range config.GetStorage() {
		if storage.GetPath() == "" {
			return fmt.Errorf("storage device %d path is required", i)
		}
		if storage.GetIsRootDevice() || i == 0 {
			hasRootDevice = true
		}
	}
	if !hasRootDevice {
		return fmt.Errorf("at least one storage device must be marked as root device")
	}

	return nil
}

// extractCustomerID extracts the customer ID for billing from VM database record
// Falls back to baggage context and finally to default customer ID
func (s *VMService) extractTenantID(ctx context.Context, vmID string) string {
	// First try to get from database (preferred source)
	if vm, err := s.vmRepo.GetVMWithContext(ctx, vmID); err == nil {
		s.logger.LogAttrs(ctx, slog.LevelDebug, "extracted customer ID from database",
			slog.String("vm_id", vmID),
			slog.String("customer_id", vm.CustomerID),
		)
		return vm.CustomerID
	} else {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "failed to get customer ID from database, trying fallback methods",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
	}

	// Fallback to baggage extraction (for compatibility with existing multi-tenant systems)
	if requestBaggage := baggage.FromContext(ctx); len(requestBaggage.Members()) > 0 {
		if tenantID := requestBaggage.Member("tenant_id").Value(); tenantID != "" {
			s.logger.LogAttrs(ctx, slog.LevelDebug, "extracted customer ID from baggage as fallback",
				slog.String("vm_id", vmID),
				slog.String("customer_id", tenantID),
			)
			return tenantID
		}
	}

	// Final fallback to default customer ID
	customerID := "default-customer"
	s.logger.LogAttrs(ctx, slog.LevelWarn, "using default customer ID for billing",
		slog.String("vm_id", vmID),
		slog.String("customer_id", customerID),
	)

	return customerID
}

// logWithTenantContext logs a message with tenant context from baggage for audit trails
func (s *VMService) logWithTenantContext(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	// Extract tenant context from baggage
	if requestBaggage := baggage.FromContext(ctx); len(requestBaggage.Members()) > 0 {
		tenantID := requestBaggage.Member("tenant_id").Value()
		projectID := requestBaggage.Member("project_id").Value()
		environmentID := requestBaggage.Member("environment_id").Value()

		// Add tenant attributes to log
		allAttrs := make([]slog.Attr, 0, len(attrs)+3)
		if tenantID != "" {
			allAttrs = append(allAttrs, slog.String("tenant_id", tenantID))
		}
		if projectID != "" {
			allAttrs = append(allAttrs, slog.String("project_id", projectID))
		}
		if environmentID != "" {
			allAttrs = append(allAttrs, slog.String("environment_id", environmentID))
		}
		allAttrs = append(allAttrs, attrs...)

		s.logger.LogAttrs(ctx, level, msg, allAttrs...)
	} else {
		// Fallback to regular logging if no baggage
		s.logger.LogAttrs(ctx, level, msg, attrs...)
	}
}

// getBackendType returns the backend type as a string for metrics
func (s *VMService) getBackendType() string {
	return "firecracker"
}

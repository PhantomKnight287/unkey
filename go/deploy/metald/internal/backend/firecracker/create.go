package firecracker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	metaldv1 "github.com/unkeyed/unkey/go/gen/proto/metal/vmprovisioner/v1"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// CreateVM creates a new VM using the SDK with integrated jailer
func (c *Client) CreateVM(ctx context.Context, config *metaldv1.VmConfig) (string, error) {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.create_vm",
		trace.WithAttributes(
			attribute.Int("vcpus", int(config.GetCpu().GetVcpuCount())),
			attribute.Int64("memory_bytes", config.GetMemory().GetSizeBytes()),
		),
	)
	defer span.End()

	// Generate VM ID
	vmID, err := generateVMID()
	if err != nil {
		span.RecordError(err)
		c.vmErrorCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", "create"),
			attribute.String("error", "generate_id"),
		))
		return "", fmt.Errorf("failed to generate VM ID: %w", err)
	}
	span.SetAttributes(attribute.String("vm_id", vmID))

	c.logger.LogAttrs(ctx, slog.LevelInfo, "creating VM",
		slog.String("vm_id", vmID),
		slog.Int("vcpus", int(config.GetCpu().GetVcpuCount())),
		slog.Int64("memory_bytes", config.GetMemory().GetSizeBytes()),
	)

	// Create VM directory
	vmDir := filepath.Join(c.baseDir, vmID)
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create VM directory: %w", err)
	}

	// Register the VM
	vm := &VM{
		ID:         vmID,
		Config:     config,
		State:      metaldv1.VmState_VM_STATE_CREATED,
		Machine:    nil, // Will be set when we boot
		CancelFunc: nil, // Will be set when we boot
	}

	c.vmRegistry[vmID] = vm

	c.vmCreateCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("status", "success"),
	))

	c.logger.LogAttrs(ctx, slog.LevelInfo, "VM created successfully with SDK v4",
		slog.String("vm_id", vmID),
	)

	return vmID, nil
}

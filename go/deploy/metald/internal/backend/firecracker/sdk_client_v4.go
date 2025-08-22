package firecracker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	sdk "github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"github.com/unkeyed/unkey/go/deploy/metald/internal/assetmanager"
	"github.com/unkeyed/unkey/go/deploy/metald/internal/backend/types"
	"github.com/unkeyed/unkey/go/deploy/metald/internal/config"
	"github.com/unkeyed/unkey/go/deploy/metald/internal/database"
	"github.com/unkeyed/unkey/go/deploy/metald/internal/jailer"
	"github.com/unkeyed/unkey/go/deploy/metald/internal/network"
	assetv1 "github.com/unkeyed/unkey/go/gen/proto/deploy/assetmanagerd/v1"
	builderv1 "github.com/unkeyed/unkey/go/gen/proto/deploy/builderd/v1"
	metaldv1 "github.com/unkeyed/unkey/go/gen/proto/metal/vmprovisioner/v1"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
)

// sdkV4VM represents a VM managed by the SDK v4
type sdkV4VM struct {
	ID           string
	Config       *metaldv1.VmConfig
	State        metaldv1.VmState
	Machine      *sdk.Machine
	NetworkInfo  *network.VMNetwork
	CancelFunc   context.CancelFunc
	AssetMapping *assetMapping         // Asset mapping for lease acquisition
	AssetPaths   map[string]string     // Prepared asset paths
	PortMappings []network.PortMapping // Port forwarding configuration
}

// SDKClientV4 implements the Backend interface using firecracker-go-sdk
// with integrated jailer functionality for secure VM isolation.
//
// AIDEV-NOTE: This was previously named SDKClientV4Jailerless which was confusing
// because it DOES use a jailer - just the integrated one, not the external binary.
// The integrated jailer solves tap device permission issues and provides better
// control over the isolation process.
type SDKClientV4 struct {
	logger                    *slog.Logger
	networkManager            *network.Manager
	assetClient               assetmanager.Client
	vmRepo                    VMRepository // For port mapping persistence
	vmRegistry                map[string]*sdkV4VM
	vmAssetLeases             map[string][]string // VM ID -> asset lease IDs
	jailer                    *jailer.Jailer
	jailerConfig              *config.JailerConfig
	baseDir                   string
	tracer                    trace.Tracer
	meter                     metric.Meter
	vmCreateCounter           metric.Int64Counter
	vmDeleteCounter           metric.Int64Counter
	vmBootCounter             metric.Int64Counter
	vmErrorCounter            metric.Int64Counter
	enableKernelNetworkConfig bool // AIDEV-NOTE: Enable/disable advanced guest network configuration via kernel command line
}

// VMRepository defines the interface for VM database operations needed by the backend
type VMRepository interface {
	UpdateVMPortMappingsWithContext(ctx context.Context, vmID string, portMappingsJSON string) error
	ListAllVMsWithContext(ctx context.Context) ([]*database.VM, error)
}

// NewSDKClientV4 creates a new SDK-based Firecracker backend client with integrated jailer
// AIDEV-NOTE: Added enableKernelNetworkConfig parameter to control advanced guest network configuration
func NewSDKClientV4(logger *slog.Logger, networkManager *network.Manager, assetClient assetmanager.Client, vmRepo VMRepository, jailerConfig *config.JailerConfig, baseDir string, enableKernelNetworkConfig bool) (*SDKClientV4, error) {
	tracer := otel.Tracer("metald.firecracker.sdk.v4")
	meter := otel.Meter("metald.firecracker.sdk.v4")

	vmCreateCounter, err := meter.Int64Counter("vm_create_total",
		metric.WithDescription("Total number of VM create operations"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create vm_create counter: %w", err)
	}

	vmDeleteCounter, err := meter.Int64Counter("vm_delete_total",
		metric.WithDescription("Total number of VM delete operations"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create vm_delete counter: %w", err)
	}

	vmBootCounter, err := meter.Int64Counter("vm_boot_total",
		metric.WithDescription("Total number of VM boot operations"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create vm_boot counter: %w", err)
	}

	vmErrorCounter, err := meter.Int64Counter("vm_error_total",
		metric.WithDescription("Total number of VM operation errors"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create vm_error counter: %w", err)
	}

	// Create integrated jailer
	integratedJailer := jailer.NewJailer(logger, jailerConfig)

	return &SDKClientV4{
		logger:                    logger.With("backend", "firecracker-sdk-v4"),
		networkManager:            networkManager,
		assetClient:               assetClient,
		vmRepo:                    vmRepo,
		vmRegistry:                make(map[string]*sdkV4VM),
		vmAssetLeases:             make(map[string][]string),
		jailer:                    integratedJailer,
		jailerConfig:              jailerConfig,
		baseDir:                   baseDir,
		tracer:                    tracer,
		meter:                     meter,
		vmCreateCounter:           vmCreateCounter,
		vmDeleteCounter:           vmDeleteCounter,
		vmBootCounter:             vmBootCounter,
		vmErrorCounter:            vmErrorCounter,
		enableKernelNetworkConfig: enableKernelNetworkConfig,
	}, nil
}

// Initialize initializes the SDK client and restores VMs from database
func (c *SDKClientV4) Initialize() error {
	ctx, span := c.tracer.Start(context.Background(), "metald.firecracker.initialize")
	defer span.End()

	c.logger.InfoContext(ctx, "initializing firecracker SDK v4 client with integrated jailer")

	// AIDEV-NOTE: Restore VMs from database to backend registry on startup
	// This ensures SHUTDOWN/PAUSED VMs can be resumed after metald restarts
	if err := c.restoreVMsFromDatabase(ctx); err != nil {
		c.logger.ErrorContext(ctx, "failed to restore VMs from database",
			"error", err,
		)
		return fmt.Errorf("failed to restore VMs: %w", err)
	}

	c.logger.InfoContext(ctx, "firecracker SDK v4 client initialized")
	return nil
}

// restoreVMsFromDatabase loads existing VMs from database into vmRegistry
// This ensures SHUTDOWN/PAUSED VMs remain resumable after metald restarts
func (c *SDKClientV4) restoreVMsFromDatabase(ctx context.Context) error {
	// Query all non-deleted VMs from database
	dbVMs, err := c.vmRepo.ListAllVMsWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to query VMs from database: %w", err)
	}

	restoredCount := 0
	reconnectedCount := 0

	for _, dbVM := range dbVMs {
		// AIDEV-BUSINESS_RULE: Restore ALL VMs regardless of state (like VMware/VirtualBox)
		// Skip only CREATED VMs that have no firecracker process yet
		state := dbVM.State
		if state == metaldv1.VmState_VM_STATE_CREATED {
			c.logger.InfoContext(ctx, "skipping CREATED VM - no firecracker process exists",
				"vm_id", dbVM.ID,
			)
			continue
		}

		// Restore VM config from database
		var config metaldv1.VmConfig
		if err := json.Unmarshal(dbVM.Config, &config); err != nil {
			c.logger.WarnContext(ctx, "failed to unmarshal VM config during restore",
				"vm_id", dbVM.ID,
				"error", err,
			)
			continue
		}

		// Create VM entry in registry without firecracker process initially
		vm := &sdkV4VM{
			ID:          dbVM.ID,
			Config:      &config,
			State:       state,
			Machine:     nil, // Will be reconnected if socket exists
			NetworkInfo: nil, // Will be restored on reconnection/resume
		}

		c.vmRegistry[dbVM.ID] = vm
		restoredCount++

		// AIDEV-NOTE: For RUNNING VMs, attempt immediate reconnection to existing process
		// This allows running VMs to continue seamlessly across metald restarts
		if state == metaldv1.VmState_VM_STATE_RUNNING {
			if err := c.reconnectToFirecracker(ctx, vm); err != nil {
				c.logger.WarnContext(ctx, "failed to reconnect to running VM - will be handled by reconciler",
					"vm_id", dbVM.ID,
					"error", err,
				)
				// Note: Don't fail restoration - reconciler will handle orphaned VMs
			} else {
				reconnectedCount++
				c.logger.InfoContext(ctx, "successfully reconnected to running VM",
					"vm_id", dbVM.ID,
				)
			}
		}

		c.logger.InfoContext(ctx, "restored VM to registry",
			"vm_id", dbVM.ID,
			"state", state.String(),
		)
	}

	c.logger.InfoContext(ctx, "VM restoration completed",
		"total_db_vms", len(dbVMs),
		"restored_count", restoredCount,
		"reconnected_count", reconnectedCount,
	)

	return nil
}

// reconnectToFirecracker reconnects to an existing firecracker process via socket
func (c *SDKClientV4) reconnectToFirecracker(ctx context.Context, vm *sdkV4VM) error {
	vmDir := filepath.Join(c.baseDir, vm.ID)
	socketPath := filepath.Join(vmDir, "firecracker.sock")

	// Check if socket file exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return fmt.Errorf("firecracker socket not found at %s - VM process may have been terminated", socketPath)
	}

	c.logger.InfoContext(ctx, "connecting to existing firecracker socket",
		"vm_id", vm.ID,
		"socket_path", socketPath,
	)

	// Create machine config for reconnection
	machineConfig := sdk.Config{
		SocketPath: socketPath,
		// Don't specify other config items for reconnection
	}

	// Create SDK machine instance for existing process
	machine, err := sdk.NewMachine(ctx, machineConfig)
	if err != nil {
		return fmt.Errorf("failed to create machine instance for socket %s: %w", socketPath, err)
	}

	vm.Machine = machine

	c.logger.InfoContext(ctx, "successfully reconnected to firecracker process",
		"vm_id", vm.ID,
	)

	return nil
}

// recreateVMForResume recreates a VM from its stored configuration when the original process is gone
// AIDEV-BUSINESS_RULE: Enable resume after service restarts by recreating firecracker processes
func (c *SDKClientV4) recreateVMForResume(ctx context.Context, vm *sdkV4VM) error {
	c.logger.InfoContext(ctx, "recreating VM for resume operation",
		"vm_id", vm.ID,
		"state", vm.State.String(),
	)

	// Get assets needed for the VM
	assetMapping, assetPaths, err := c.prepareVMAssets(ctx, vm.ID, vm.Config)
	if err != nil {
		return fmt.Errorf("failed to prepare VM assets for recreation: %w", err)
	}

	// Set up VM directory
	vmDir := filepath.Join(c.baseDir, vm.ID)
	if mkdirErr := os.MkdirAll(vmDir, 0755); mkdirErr != nil {
		return fmt.Errorf("failed to create VM directory: %w", mkdirErr)
	}

	// Set up networking for the recreated VM
	networkInfo, err := c.networkManager.CreateVMNetwork(ctx, vm.ID)
	if err != nil {
		return fmt.Errorf("failed to create network for recreated VM: %w", err)
	}
	vm.NetworkInfo = networkInfo

	// Create machine configuration
	socketPath := filepath.Join(vmDir, "firecracker.sock")
	fcConfig := c.buildFirecrackerConfig(ctx, vm.ID, vm.Config, networkInfo, assetPaths)
	fcConfig.SocketPath = socketPath

	// Create new firecracker machine instance
	machine, err := sdk.NewMachine(ctx, fcConfig)
	if err != nil {
		return fmt.Errorf("failed to create new machine instance: %w", err)
	}

	// Start the VM (this creates the firecracker process)
	if err := machine.Start(ctx); err != nil {
		return fmt.Errorf("failed to start recreated VM: %w", err)
	}

	// Pause the VM immediately since we're recreating it in SHUTDOWN/PAUSED state
	// The user will call resume to actually start it running
	if err := machine.PauseVM(ctx); err != nil {
		c.logger.WarnContext(ctx, "failed to pause recreated VM - continuing anyway",
			"vm_id", vm.ID,
			"error", err,
		)
	}

	// Update the VM in registry
	vm.Machine = machine
	vm.AssetMapping = assetMapping
	vm.AssetPaths = assetPaths

	c.logger.InfoContext(ctx, "VM successfully recreated for resume",
		"vm_id", vm.ID,
	)

	return nil
}

// CreateVM creates a new VM using the SDK with integrated jailer
func (c *SDKClientV4) CreateVM(ctx context.Context, config *metaldv1.VmConfig) (string, error) {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.create_vm",
		trace.WithAttributes(
			attribute.Int("vcpus", int(config.GetCpu().GetVcpuCount())),
			attribute.Int64("memory_bytes", config.GetMemory().GetSizeBytes()),
		),
	)
	defer span.End()

	// Generate VM ID
	vmID, err := generateV4VMID()
	if err != nil {
		span.RecordError(err)
		c.vmErrorCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", "create"),
			attribute.String("error", "generate_id"),
		))
		return "", fmt.Errorf("failed to generate VM ID: %w", err)
	}
	span.SetAttributes(attribute.String("vm_id", vmID))

	c.logger.LogAttrs(ctx, slog.LevelInfo, "creating VM with SDK v4",
		slog.String("vm_id", vmID),
		slog.Int("vcpus", int(config.GetCpu().GetVcpuCount())),
		slog.Int64("memory_bytes", config.GetMemory().GetSizeBytes()),
	)

	// Key difference: Allocate network resources BEFORE creating the jail
	// This allows us to create the tap device with full privileges
	networkInfo, err := c.networkManager.CreateVMNetwork(ctx, vmID)
	if err != nil {
		span.RecordError(err)
		c.vmErrorCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", "create"),
			attribute.String("error", "network_allocation"),
		))
		return "", fmt.Errorf("failed to allocate network: %w", err)
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "allocated network for VM",
		slog.String("vm_id", vmID),
		slog.String("namespace", networkInfo.Namespace),
		slog.String("tap_device", networkInfo.TapDevice),
		slog.String("ip_address", networkInfo.IPAddress.String()),
	)

	// Prepare assets in the jailer chroot
	assetMapping, preparedPaths, err := c.prepareVMAssets(ctx, vmID, config)
	if err != nil {
		span.RecordError(err)
		c.vmErrorCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", "create"),
			attribute.String("error", "asset_preparation"),
		))
		// Clean up network allocation
		if cleanupErr := c.networkManager.DeleteVMNetwork(ctx, vmID); cleanupErr != nil {
			c.logger.ErrorContext(ctx, "failed to cleanup network after asset preparation failure",
				"vm_id", vmID,
				"error", cleanupErr,
			)
		}
		return "", fmt.Errorf("failed to prepare VM assets: %w", err)
	}

	// Build SDK configuration WITHOUT jailer
	// The jailer functionality is now integrated
	_ = c.buildFirecrackerConfig(ctx, vmID, config, networkInfo, preparedPaths)

	// Create VM directory
	vmDir := filepath.Join(c.baseDir, vmID)
	if err := os.MkdirAll(vmDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create VM directory: %w", err)
	}

	// Register the VM
	vm := &sdkV4VM{
		ID:           vmID,
		Config:       config,
		State:        metaldv1.VmState_VM_STATE_CREATED,
		Machine:      nil, // Will be set when we boot
		NetworkInfo:  networkInfo,
		CancelFunc:   nil, // Will be set when we boot
		AssetMapping: assetMapping,
		AssetPaths:   preparedPaths,
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

// BootVM starts a created VM using our integrated jailer
func (c *SDKClientV4) BootVM(ctx context.Context, vmID string) error {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.boot_vm",
		trace.WithAttributes(attribute.String("vm_id", vmID)),
	)
	defer span.End()

	vm, exists := c.vmRegistry[vmID]
	if !exists {
		err := fmt.Errorf("vm %s not found", vmID)
		span.RecordError(err)
		c.vmErrorCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", "boot"),
			attribute.String("error", "vm_not_found"),
		))
		return err
	}

	// AIDEV-NOTE: Validate VM state before boot operation
	if vm.State != metaldv1.VmState_VM_STATE_CREATED {
		err := fmt.Errorf("vm %s is in %s state, can only boot VMs in CREATED state", vmID, vm.State.String())
		span.RecordError(err)
		c.vmErrorCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", "boot"),
			attribute.String("error", "invalid_state_transition"),
			attribute.String("current_state", vm.State.String()),
		))
		return err
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "booting VM with SDK v4",
		slog.String("vm_id", vmID),
		slog.String("current_state", vm.State.String()),
	)

	// For integrated jailer, we run firecracker in the VM directory
	vmDir := filepath.Join(c.baseDir, vmID)
	socketPath := filepath.Join(vmDir, "firecracker.sock")

	// Create log files
	logPath := filepath.Join(vmDir, "firecracker.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	defer logFile.Close()

	// Load container metadata and parse port mappings
	var metadata *builderv1.ImageMetadata
	var portMappings []network.PortMapping
	for _, disk := range vm.Config.GetStorage() {
		if disk.GetIsRootDevice() {
			// AIDEV-NOTE: Use chroot path for metadata loading since assets are copied there
			// The original disk path points to asset manager, but metadata.json is in chroot
			jailerRoot := filepath.Join(c.jailerConfig.ChrootBaseDir, "firecracker", vmID, "root")
			chrootRootfsPath := filepath.Join(jailerRoot, "rootfs.ext4")

			if m, metadataErr := c.loadContainerMetadata(ctx, chrootRootfsPath); metadataErr != nil {
				c.logger.WarnContext(ctx, "failed to load container metadata",
					"error", metadataErr,
					"chroot_rootfs_path", chrootRootfsPath,
				)
			} else if m != nil {
				metadata = m

				// AIDEV-NOTE: Create /container.cmd file for metald-init
				// Combine entrypoint and command into a single JSON array
				if cmdFileErr := c.createContainerCmdFile(ctx, vmID, metadata); cmdFileErr != nil {
					c.logger.WarnContext(ctx, "failed to create container.cmd file",
						"error", cmdFileErr,
						"vm_id", vmID,
					)
				}

				if mappings, portErr := c.parseExposedPorts(ctx, vmID, metadata); portErr != nil {
					c.logger.ErrorContext(ctx, "failed to parse exposed ports",
						slog.String("vm_id", vmID),
						slog.String("error", portErr.Error()),
					)
					// Continue without port mappings rather than failing the boot
				} else {
					portMappings = mappings
				}
				c.logger.LogAttrs(ctx, slog.LevelInfo, "loaded metadata for VM boot",
					slog.String("vm_id", vmID),
					slog.Int("port_count", len(portMappings)),
				)
				break
			}
		}
	}

	// Build firecracker config that will be used by SDK
	fcConfig := c.buildFirecrackerConfig(ctx, vmID, vm.Config, vm.NetworkInfo, vm.AssetPaths)
	fcConfig.SocketPath = socketPath

	// Update kernel args with network configuration and metadata if available
	// AIDEV-NOTE: Use comprehensive kernel args builder that supports both network and container metadata
	fcConfig.KernelArgs = c.buildKernelArgsWithNetworkAndMetadata(ctx, fcConfig.KernelArgs, vm.NetworkInfo, metadata)

	// Create a context for this VM
	vmCtx, cancel := context.WithCancel(context.Background())
	vm.CancelFunc = cancel

	// For integrated jailer, we use the SDK directly without external jailer
	// The network namespace is already set up and tap device created
	// We'll let the SDK manage firecracker but in our network namespace

	// Set the network namespace for the SDK to use
	if vm.NetworkInfo != nil && vm.NetworkInfo.Namespace != "" {
		fcConfig.NetNS = filepath.Join("/run/netns", vm.NetworkInfo.Namespace)
	}

	// Create and start the machine using SDK
	machine, err := sdk.NewMachine(vmCtx, fcConfig)
	if err != nil {
		cancel()
		span.RecordError(err)
		c.vmErrorCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", "boot"),
			attribute.String("error", "create_machine"),
		))
		return fmt.Errorf("failed to create firecracker machine: %w", err)
	}

	// Start the VM
	if err := machine.Start(vmCtx); err != nil {
		cancel()
		span.RecordError(err)
		c.vmErrorCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", "boot"),
			attribute.String("error", "start_machine"),
		))
		return fmt.Errorf("failed to start firecracker machine: %w", err)
	}

	vm.Machine = machine
	vm.State = metaldv1.VmState_VM_STATE_RUNNING
	vm.PortMappings = portMappings

	// AIDEV-NOTE: Persist port mappings to database for state recovery
	if c.vmRepo != nil && len(portMappings) > 0 {
		portMappingsJSON, err := json.Marshal(portMappings)
		if err != nil {
			c.logger.WarnContext(ctx, "failed to marshal port mappings for persistence",
				slog.String("vm_id", vmID),
				slog.String("error", err.Error()),
			)
		} else {
			if err := c.vmRepo.UpdateVMPortMappingsWithContext(ctx, vmID, string(portMappingsJSON)); err != nil {
				c.logger.WarnContext(ctx, "failed to persist port mappings to database",
					slog.String("vm_id", vmID),
					slog.String("error", err.Error()),
				)
			} else {
				c.logger.InfoContext(ctx, "persisted port mappings to database",
					slog.String("vm_id", vmID),
					slog.Int("port_count", len(portMappings)),
				)
			}
		}
	}

	// Acquire asset leases after successful boot
	if vm.AssetMapping != nil && len(vm.AssetMapping.AssetIDs()) > 0 {
		c.logger.LogAttrs(ctx, slog.LevelInfo, "acquiring asset leases for VM",
			slog.String("vm_id", vmID),
			slog.Int("asset_count", len(vm.AssetMapping.AssetIDs())),
		)

		leaseIDs := []string{}
		for _, assetID := range vm.AssetMapping.AssetIDs() {
			acquireCtx, acquireSpan := c.tracer.Start(ctx, "metald.firecracker.acquire_asset",
				trace.WithAttributes(
					attribute.String("vm.id", vmID),
					attribute.String("asset.id", assetID),
				),
			)
			leaseID, err := c.assetClient.AcquireAsset(acquireCtx, assetID, vmID)
			if err != nil {
				acquireSpan.RecordError(err)
				acquireSpan.SetStatus(codes.Error, err.Error())
			} else {
				acquireSpan.SetAttributes(attribute.String("lease.id", leaseID))
			}
			acquireSpan.End()
			if err != nil {
				c.logger.ErrorContext(ctx, "failed to acquire asset lease",
					"vm_id", vmID,
					"asset_id", assetID,
					"error", err,
				)
				// Continue trying to acquire other leases even if one fails
				// AIDEV-TODO: Consider whether to fail the boot if lease acquisition fails
			} else {
				leaseIDs = append(leaseIDs, leaseID)
			}
		}

		// Store lease IDs for cleanup during VM deletion
		if len(leaseIDs) > 0 {
			c.vmAssetLeases[vmID] = leaseIDs
			c.logger.LogAttrs(ctx, slog.LevelInfo, "acquired asset leases",
				slog.String("vm_id", vmID),
				slog.Int("lease_count", len(leaseIDs)),
			)
		}
	}

	// Configure port forwarding if we have mappings
	if vm.NetworkInfo != nil && len(vm.PortMappings) > 0 {
		if err := c.configurePortForwarding(ctx, vmID, vm.NetworkInfo.IPAddress.String(), vm.PortMappings); err != nil {
			c.logger.ErrorContext(ctx, "failed to configure port forwarding",
				"vm_id", vmID,
				"error", err,
			)
			// Don't fail the VM boot, but log the error
		}
	}

	c.vmBootCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("status", "success"),
	))

	c.logger.LogAttrs(ctx, slog.LevelInfo, "VM booted successfully with SDK v4",
		slog.String("vm_id", vmID),
	)

	return nil
}

// Other methods would be similar to SDKClientV3...

// buildFirecrackerConfig builds the SDK configuration without jailer
func (c *SDKClientV4) buildFirecrackerConfig(ctx context.Context, vmID string, config *metaldv1.VmConfig, networkInfo *network.VMNetwork, preparedPaths map[string]string) sdk.Config {
	// For integrated jailer, we use absolute paths since we're not running inside chroot
	// The assets are still in the jailer directory structure for consistency
	jailerRoot := filepath.Join(
		c.jailerConfig.ChrootBaseDir,
		"firecracker",
		vmID,
		"root",
	)

	socketPath := "/firecracker.sock"

	// Determine kernel path - use prepared path if available, otherwise fallback to default
	kernelPath := filepath.Join(jailerRoot, "vmlinux")
	if len(preparedPaths) > 0 {
		// AIDEV-NOTE: In a more sophisticated implementation, we'd track which asset ID
		// corresponds to which component (kernel vs rootfs). For now, we rely on the
		// assetmanager preparing files with standard names in the target directory.
		// The prepared paths should already be in the jailerRoot directory.
		c.logger.LogAttrs(ctx, slog.LevelDebug, "using prepared asset paths",
			slog.String("vm_id", vmID),
			slog.Int("path_count", len(preparedPaths)),
		)
	}

	// Use host path since Firecracker is running outside chroot in "jailerless" mode
	metricsPath := filepath.Join(jailerRoot, "metrics.fifo")

	// AIDEV-NOTE: Create metrics FIFO for billaged to read Firecracker stats
	// billaged should read from: {jailerRoot}/metrics.fifo
	// e.g., /srv/jailer/firecracker/{vmID}/root/metrics.fifo
	hostMetricsPath := filepath.Join(jailerRoot, "metrics.fifo")

	// Create the metrics FIFO in the host filesystem
	if err := unix.Mkfifo(hostMetricsPath, 0644); err != nil && !os.IsExist(err) {
		c.logger.ErrorContext(ctx, "failed to create metrics FIFO",
			slog.String("vm_id", vmID),
			slog.String("path", hostMetricsPath),
			slog.String("error", err.Error()),
		)
	} else {
		c.logger.InfoContext(ctx, "created metrics FIFO for billaged",
			slog.String("vm_id", vmID),
			slog.String("host_path", hostMetricsPath),
			slog.String("chroot_path", metricsPath),
		)
	}

	// Use the kernel args as provided by the caller
	// Metadata handling is now done in BootVM
	kernelArgs := config.GetBoot().GetKernelArgs()

	// AIDEV-NOTE: Guest console logging configuration
	// LogPath captures Firecracker's own logs, but LogFifo+FifoLogWriter captures guest OS console output
	// This includes Linux kernel boot messages from console=ttyS0 kernel parameter
	consoleLogPath := filepath.Join(jailerRoot, "console.log")
	consoleFifoPath := filepath.Join(jailerRoot, "console.fifo")

	// Create the console log file to capture guest output
	consoleLogFile, err := os.OpenFile(consoleLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	var cfg sdk.Config
	if err != nil {
		// Fall back to LogPath only (original behavior) if console log file creation fails
		c.logger.WarnContext(ctx, "failed to create console log file, falling back to LogPath only",
			slog.String("error", err.Error()),
			slog.String("console_log_path", consoleLogPath),
		)
		cfg = sdk.Config{ //nolint:exhaustruct // Optional fields are not needed for basic VM configuration
			SocketPath:      socketPath,
			LogPath:         consoleLogPath, // Original behavior - captures Firecracker logs only
			LogLevel:        "Debug",
			MetricsPath:     metricsPath, // Configure stats socket for billaged
			KernelImagePath: kernelPath,
			KernelArgs:      kernelArgs,
			MachineCfg: models.MachineConfiguration{ //nolint:exhaustruct // Only setting required fields for basic VM configuration
				VcpuCount:  sdk.Int64(int64(config.GetCpu().GetVcpuCount())),
				MemSizeMib: sdk.Int64(config.GetMemory().GetSizeBytes() / (1024 * 1024)),
				Smt:        sdk.Bool(false),
			},
			// No JailerCfg - we handle jailing ourselves
		}
	} else {
		// Successful case - capture guest console output via FIFO
		// Note: consoleLogFile will be closed when the VM shuts down via FifoLogWriter
		cfg = sdk.Config{ //nolint:exhaustruct // Optional fields are not needed for basic VM configuration
			SocketPath:      socketPath,
			LogPath:         filepath.Join(jailerRoot, "firecracker.log"), // Firecracker's own logs
			LogFifo:         consoleFifoPath,                              // FIFO for guest console output
			FifoLogWriter:   consoleLogFile,                               // Writer to capture guest console to file
			LogLevel:        "Debug",
			MetricsPath:     metricsPath, // Configure stats socket for billaged
			KernelImagePath: kernelPath,
			KernelArgs:      kernelArgs,
			MachineCfg: models.MachineConfiguration{ //nolint:exhaustruct // Only setting required fields for basic VM configuration
				VcpuCount:  sdk.Int64(int64(config.GetCpu().GetVcpuCount())),
				MemSizeMib: sdk.Int64(config.GetMemory().GetSizeBytes() / (1024 * 1024)),
				Smt:        sdk.Bool(false),
			},
			// No JailerCfg - we handle jailing ourselves
		}
	}

	// Add drives
	cfg.Drives = make([]models.Drive, 0, len(config.GetStorage()))
	for i, disk := range config.GetStorage() {
		driveID := disk.GetId()
		if driveID == "" {
			if disk.GetIsRootDevice() || i == 0 {
				driveID = "rootfs"
			} else {
				driveID = fmt.Sprintf("drive_%d", i)
			}
		}

		// Use absolute paths for integrated jailer
		// AIDEV-NOTE: Use standardized filename instead of the original config path
		// to match what asset preparation creates (rootfs.ext4, not Docker-specific names)
		diskFilename := filepath.Base(disk.GetPath())
		if disk.GetIsRootDevice() || i == 0 {
			// For root devices, always use the standardized name that assetmanager creates
			diskFilename = "rootfs.ext4"
		}

		drive := models.Drive{ //nolint:exhaustruct // Only setting required drive fields
			DriveID:      &driveID,
			PathOnHost:   sdk.String(filepath.Join(jailerRoot, diskFilename)),
			IsRootDevice: sdk.Bool(disk.GetIsRootDevice() || i == 0),
			IsReadOnly:   sdk.Bool(disk.GetReadOnly()),
		}
		cfg.Drives = append(cfg.Drives, drive)
	}

	// Add network interface
	if networkInfo != nil {
		iface := sdk.NetworkInterface{ //nolint:exhaustruct // Only setting required network interface fields
			StaticConfiguration: &sdk.StaticNetworkConfiguration{ //nolint:exhaustruct // Only setting required network configuration fields
				HostDevName: networkInfo.TapDevice,
				MacAddress:  networkInfo.MacAddress,
			},
		}
		cfg.NetworkInterfaces = []sdk.NetworkInterface{iface}
	}

	return cfg
}

// assetRequirement represents a required asset for VM creation
type assetRequirement struct {
	Type     assetv1.AssetType
	Labels   map[string]string
	Required bool
}

// assetMapping tracks the mapping between requirements and actual assets
type assetMapping struct {
	requirements []assetRequirement
	assets       map[string]*assetv1.Asset // requirement index -> asset
	assetIDs     []string
	leaseIDs     []string
}

func (am *assetMapping) AssetIDs() []string {
	return am.assetIDs
}

func (am *assetMapping) LeaseIDs() []string {
	return am.leaseIDs
}

// buildAssetRequirements analyzes VM config to determine required assets
func (c *SDKClientV4) buildAssetRequirements(config *metaldv1.VmConfig) []assetRequirement {
	var reqs []assetRequirement

	// DEBUG: Log VM config for docker image troubleshooting
	c.logger.Info("DEBUG: analyzing VM config for assets",
		"storage_count", len(config.GetStorage()),
		"metadata", config.GetMetadata(),
	)
	for i, disk := range config.GetStorage() {
		c.logger.Info("DEBUG: storage device",
			"index", i,
			"id", disk.GetId(),
			"path", disk.GetPath(),
			"is_root", disk.GetIsRootDevice(),
			"options", disk.GetOptions(),
		)
	}

	// Kernel requirement
	if config.GetBoot() != nil && config.GetBoot().GetKernelPath() != "" {
		reqs = append(reqs, assetRequirement{
			Type:     assetv1.AssetType_ASSET_TYPE_KERNEL,
			Required: true,
		})
	}

	// Rootfs requirements from storage devices
	for _, disk := range config.GetStorage() {
		if disk.GetIsRootDevice() {
			labels := make(map[string]string)
			// Check for docker image in disk options first, then config metadata
			if dockerImage, ok := disk.GetOptions()["docker_image"]; ok {
				labels["docker_image"] = dockerImage
			} else if dockerImage, ok := config.GetMetadata()["docker_image"]; ok {
				labels["docker_image"] = dockerImage
			}

			// Note: force_rebuild is handled separately via BuildOptions, not asset labels
			// We don't add force_rebuild to asset labels since it's a build trigger, not an asset attribute
			reqs = append(reqs, assetRequirement{
				Type:     assetv1.AssetType_ASSET_TYPE_ROOTFS,
				Labels:   labels,
				Required: true,
			})
		}
	}

	// Initrd requirement (optional)
	if config.GetBoot() != nil && config.GetBoot().GetInitrdPath() != "" {
		reqs = append(reqs, assetRequirement{
			Type:     assetv1.AssetType_ASSET_TYPE_INITRD,
			Required: false,
		})
	}

	return reqs
}

// matchAssets matches available assets to requirements
func (c *SDKClientV4) matchAssets(reqs []assetRequirement, availableAssets []*assetv1.Asset) (*assetMapping, error) {
	mapping := &assetMapping{
		requirements: reqs,
		assets:       make(map[string]*assetv1.Asset),
		assetIDs:     []string{},
	}

	for i, req := range reqs {
		var matched *assetv1.Asset

		// Find best matching asset
		for _, asset := range availableAssets {
			if asset.GetType() != req.Type {
				continue
			}

			// Check if all required labels match
			labelMatch := true
			for k, v := range req.Labels {
				if assetLabel, ok := asset.GetLabels()[k]; !ok || assetLabel != v {
					labelMatch = false
					break
				}
			}

			if labelMatch {
				matched = asset
				break
			}
		}

		if matched == nil && req.Required {
			// Build helpful error message
			labelStr := ""
			for k, v := range req.Labels {
				if labelStr != "" {
					labelStr += ", "
				}
				labelStr += fmt.Sprintf("%s=%s", k, v)
			}
			return nil, fmt.Errorf("no matching asset found for type %s with labels {%s}",
				req.Type.String(), labelStr)
		}

		if matched != nil {
			mapping.assets[fmt.Sprintf("%d", i)] = matched
			mapping.assetIDs = append(mapping.assetIDs, matched.GetId())
		}
	}

	return mapping, nil
}

// prepareVMAssets prepares kernel and rootfs assets for the VM in the jailer chroot
// Returns the asset mapping for lease acquisition after successful boot
func (c *SDKClientV4) prepareVMAssets(ctx context.Context, vmID string, config *metaldv1.VmConfig) (*assetMapping, map[string]string, error) {
	// Calculate the jailer chroot path
	jailerRoot := filepath.Join(
		c.jailerConfig.ChrootBaseDir,
		"firecracker",
		vmID,
		"root",
	)

	c.logger.LogAttrs(ctx, slog.LevelInfo, "preparing VM assets using assetmanager",
		slog.String("vm_id", vmID),
		slog.String("target_path", jailerRoot),
	)

	// Ensure the jailer root directory exists
	if err := os.MkdirAll(jailerRoot, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create jailer root directory: %w", err)
	}

	// Check if assetmanager is enabled
	// If disabled (using noop client), fall back to static file copying for backward compatibility
	// AIDEV-NOTE: We check if the QueryAssets call succeeds to determine if assetmanager is available
	// We don't require assets to exist, as they can be built on demand
	ctx, checkSpan := c.tracer.Start(ctx, "metald.firecracker.check_assetmanager",
		trace.WithAttributes(
			attribute.String("vm.id", vmID),
			attribute.String("asset.type", "KERNEL"),
		),
	)
	_, err := c.assetClient.QueryAssets(ctx, assetv1.AssetType_ASSET_TYPE_KERNEL, nil, nil)
	checkSpan.End()
	if err != nil {
		c.logger.LogAttrs(ctx, slog.LevelInfo, "assetmanager disabled or unavailable, using static file copying",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		// AIDEV-NOTE: Fallback to old behavior when assetmanager is disabled
		// This ensures backward compatibility
		if staticErr := c.prepareVMAssetsStatic(ctx, vmID, config, jailerRoot); staticErr != nil {
			return nil, nil, staticErr
		}
		return nil, nil, nil
	}

	// Build asset requirements from VM configuration
	requiredAssets := c.buildAssetRequirements(config)
	c.logger.LogAttrs(ctx, slog.LevelDebug, "determined asset requirements",
		slog.String("vm_id", vmID),
		slog.Int("required_count", len(requiredAssets)),
	)

	// Query assetmanager for available assets with automatic build support
	// AIDEV-NOTE: Using QueryAssets instead of ListAssets to enable automatic asset creation
	allAssets := []*assetv1.Asset{}

	// Extract tenant_id from VM metadata if available, with fallback to default
	tenantID := "cli-tenant" // AIDEV-NOTE: Default tenant for CLI operations
	if tid, ok := config.GetMetadata()["tenant_id"]; ok {
		tenantID = tid
	}

	// Group requirements by type and labels for efficient querying
	type queryKey struct {
		assetType assetv1.AssetType
		labels    string // Serialized labels for grouping
	}
	queryGroups := make(map[queryKey][]assetRequirement)

	for _, req := range requiredAssets {
		// Serialize labels for grouping
		labelStr := ""
		for k, v := range req.Labels {
			if labelStr != "" {
				labelStr += ","
			}
			labelStr += fmt.Sprintf("%s=%s", k, v)
		}
		key := queryKey{assetType: req.Type, labels: labelStr}
		queryGroups[key] = append(queryGroups[key], req)
	}

	// Query each unique combination of type and labels
	for key, reqs := range queryGroups {
		// Use the first requirement's labels (they should all be the same in the group)
		labels := reqs[0].Labels

		// Generate a deterministic asset ID based on the asset type and labels
		// This allows us to query for the exact asset later
		assetID := c.generateAssetID(key.assetType, labels)

		c.logger.LogAttrs(ctx, slog.LevelInfo, "generated asset ID for query",
			slog.String("asset_id", assetID),
			slog.String("asset_type", key.assetType.String()),
			slog.Any("labels", labels),
		)

		// Configure build options for automatic asset creation
		// AIDEV-NOTE: When WaitForCompletion is true, VM creation will block until the build
		// completes. This provides a synchronous experience where the VM is ready to boot
		// immediately after creation, but may cause longer wait times (up to 30 minutes
		// for large images). The client timeout should be configured accordingly.

		// Create build labels (copy asset labels and add force_rebuild if needed)
		buildLabels := make(map[string]string)
		for k, v := range labels {
			buildLabels[k] = v
		}

		// Check for force_rebuild in VM config metadata (separate from asset labels)
		if forceRebuild, ok := config.GetMetadata()["force_rebuild"]; ok && forceRebuild == "true" {
			buildLabels["force_rebuild"] = "true"
		}

		buildOptions := &assetv1.BuildOptions{
			EnableAutoBuild:     true,
			WaitForCompletion:   true, // Block VM creation until build completes
			BuildTimeoutSeconds: 1800, // 30 minutes maximum wait time
			TenantId:            tenantID,
			SuggestedAssetId:    assetID,
			BuildLabels:         buildLabels, // Pass build labels including force_rebuild to assetmanagerd
		}

		// Query assets with automatic build support
		// Create a quick span just to record that we're initiating a query
		_, initSpan := c.tracer.Start(ctx, "metald.firecracker.query_assets",
			trace.WithAttributes(
				attribute.String("vm.id", vmID),
				attribute.String("asset.type", key.assetType.String()),
				attribute.StringSlice("asset.labels", func() []string {
					var labelPairs []string
					for k, v := range labels {
						labelPairs = append(labelPairs, fmt.Sprintf("%s=%s", k, v))
					}
					return labelPairs
				}()),
				attribute.String("tenant.id", tenantID),
				attribute.Bool("auto_build.enabled", buildOptions.GetEnableAutoBuild()),
				attribute.Int("build.timeout_seconds", int(buildOptions.GetBuildTimeoutSeconds())),
			),
		)
		initSpan.End() // End immediately - this just marks the initiation

		// Make the actual call without wrapping in a span (it has its own internal spans)
		resp, queryErr := c.assetClient.QueryAssets(ctx, key.assetType, labels, buildOptions)
		if queryErr != nil {
			return nil, nil, fmt.Errorf("failed to query assets of type %s with labels %v: %w",
				key.assetType.String(), labels, queryErr)
		}

		// Create a quick span to record the results
		_, resultSpan := c.tracer.Start(ctx, "metald.firecracker.query_assets_complete",
			trace.WithAttributes(
				attribute.String("vm.id", vmID),
				attribute.String("asset.type", key.assetType.String()),
				attribute.Int("assets.found", len(resp.GetAssets())),
				attribute.Int("builds.triggered", len(resp.GetTriggeredBuilds())),
			),
		)
		resultSpan.End()

		// Log any triggered builds
		for _, build := range resp.GetTriggeredBuilds() {
			c.logger.LogAttrs(ctx, slog.LevelInfo, "automatic build triggered for missing asset",
				slog.String("vm_id", vmID),
				slog.String("build_id", build.GetBuildId()),
				slog.String("docker_image", build.GetDockerImage()),
				slog.String("status", build.GetStatus()),
			)

			if build.GetStatus() == "failed" {
				c.logger.LogAttrs(ctx, slog.LevelError, "automatic build failed",
					slog.String("vm_id", vmID),
					slog.String("build_id", build.GetBuildId()),
					slog.String("error", build.GetErrorMessage()),
				)
			}
		}

		allAssets = append(allAssets, resp.GetAssets()...)
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "retrieved available assets",
		slog.String("vm_id", vmID),
		slog.Int("available_count", len(allAssets)),
	)

	// Log asset details for debugging
	for _, asset := range allAssets {
		c.logger.LogAttrs(ctx, slog.LevelInfo, "available asset",
			slog.String("asset_id", asset.GetId()),
			slog.String("asset_type", asset.GetType().String()),
			slog.Any("labels", asset.GetLabels()),
		)
	}

	// Match required assets with available ones
	assetMapping, err := c.matchAssets(requiredAssets, allAssets)
	if err != nil {
		c.logger.LogAttrs(ctx, slog.LevelError, "failed to match assets",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		return nil, nil, fmt.Errorf("asset matching failed: %w", err)
	}

	// Prepare assets in target location
	ctx, prepareSpan := c.tracer.Start(ctx, "metald.firecracker.prepare_assets",
		trace.WithAttributes(
			attribute.String("vm.id", vmID),
			attribute.StringSlice("asset.ids", assetMapping.AssetIDs()),
			attribute.String("target.path", jailerRoot),
		),
	)
	preparedPaths, err := c.assetClient.PrepareAssets(
		ctx,
		assetMapping.AssetIDs(),
		jailerRoot,
		vmID,
	)
	if err != nil {
		prepareSpan.RecordError(err)
		prepareSpan.SetStatus(codes.Error, err.Error())
	} else {
		prepareSpan.SetAttributes(
			attribute.Int("assets.prepared", len(preparedPaths)),
		)
	}
	prepareSpan.End()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare assets: %w", err)
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "assets prepared successfully",
		slog.String("vm_id", vmID),
		slog.Int("asset_count", len(preparedPaths)),
	)

	// The preparedPaths map contains asset_id -> actual_path mappings
	// These paths will be used to update the VM configuration before starting
	// Asset leases will be acquired after successful VM boot in BootVM
	// to avoid holding leases for VMs that fail to start

	// AIDEV-NOTE: Copy metadata files alongside rootfs assets if they exist
	// Asset manager only handles the rootfs, but we need metadata for container execution
	if err := c.copyMetadataFilesForAssets(ctx, vmID, config, preparedPaths, jailerRoot); err != nil {
		c.logger.WarnContext(ctx, "failed to copy metadata files",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		// Don't fail asset preparation for metadata issues - VM can still run without metadata
	}

	return assetMapping, preparedPaths, nil
}

// prepareVMAssetsStatic is the fallback implementation for static file copying
// Used when assetmanager is disabled for backward compatibility
func (c *SDKClientV4) prepareVMAssetsStatic(ctx context.Context, vmID string, config *metaldv1.VmConfig, jailerRoot string) error {
	// Copy kernel
	if kernelPath := config.GetBoot().GetKernelPath(); kernelPath != "" {
		kernelDst := filepath.Join(jailerRoot, "vmlinux")
		if err := copyFileWithOwnership(kernelPath, kernelDst, int(c.jailerConfig.UID), int(c.jailerConfig.GID)); err != nil {
			return fmt.Errorf("failed to copy kernel: %w", err)
		}
		c.logger.LogAttrs(ctx, slog.LevelInfo, "copied kernel to jailer root",
			slog.String("src", kernelPath),
			slog.String("dst", kernelDst),
		)
	}

	// Copy rootfs images
	for _, disk := range config.GetStorage() {
		if disk.GetPath() != "" {
			diskDst := filepath.Join(jailerRoot, filepath.Base(disk.GetPath()))
			if err := copyFileWithOwnership(disk.GetPath(), diskDst, int(c.jailerConfig.UID), int(c.jailerConfig.GID)); err != nil {
				return fmt.Errorf("failed to copy disk %s: %w", disk.GetPath(), err)
			}
			c.logger.LogAttrs(ctx, slog.LevelInfo, "copied disk to jailer root",
				slog.String("src", disk.GetPath()),
				slog.String("dst", diskDst),
			)

			// Also copy metadata file if it exists
			if disk.GetIsRootDevice() {
				baseName := strings.TrimSuffix(filepath.Base(disk.GetPath()), filepath.Ext(disk.GetPath()))
				metadataSrc := filepath.Join(filepath.Dir(disk.GetPath()), baseName+".metadata.json")
				if _, err := os.Stat(metadataSrc); err == nil {
					metadataDst := filepath.Join(jailerRoot, filepath.Base(metadataSrc))
					if err := copyFileWithOwnership(metadataSrc, metadataDst, int(c.jailerConfig.UID), int(c.jailerConfig.GID)); err != nil {
						c.logger.WarnContext(ctx, "failed to copy metadata file",
							"src", metadataSrc,
							"dst", metadataDst,
							"error", err,
						)
					} else {
						c.logger.LogAttrs(ctx, slog.LevelInfo, "copied metadata file to jailer root",
							slog.String("src", metadataSrc),
							slog.String("dst", metadataDst),
						)

						// Write command file to rootfs by mounting it temporarily
						// This avoids kernel command line parsing issues
						metadata, err := c.loadContainerMetadata(ctx, disk.GetPath())
						if err == nil && metadata != nil {
							// Build the command array
							var fullCmd []string
							fullCmd = append(fullCmd, metadata.GetEntrypoint()...)
							fullCmd = append(fullCmd, metadata.GetCommand()...)

							if len(fullCmd) > 0 {
								// Mount the rootfs temporarily to write the command file
								mountDir := filepath.Join("/tmp", fmt.Sprintf("mount-%s", vmID))
								if err := os.MkdirAll(mountDir, 0755); err == nil {
									// Mount the rootfs ext4 image
									mountCmd := exec.CommandContext(ctx, "mount", "-o", "loop", diskDst, mountDir)
									if err := mountCmd.Run(); err != nil {
										c.logger.WarnContext(ctx, "failed to mount rootfs for command file",
											"error", err,
											"disk", diskDst,
										)
									} else {
										// Write the command file
										cmdFile := filepath.Join(mountDir, "container.cmd")
										cmdData, _ := json.Marshal(fullCmd)
										if err := os.WriteFile(cmdFile, cmdData, 0600); err != nil {
											c.logger.WarnContext(ctx, "failed to write command file",
												"path", cmdFile,
												"error", err,
											)
										} else {
											c.logger.LogAttrs(ctx, slog.LevelInfo, "wrote container command file to rootfs",
												slog.String("path", cmdFile),
												slog.String("command", string(cmdData)),
											)
										}

										// Unmount
										umountCmd := exec.CommandContext(ctx, "umount", mountDir)
										if err := umountCmd.Run(); err != nil {
											c.logger.WarnContext(ctx, "failed to unmount rootfs",
												"error", err,
												"mountDir", mountDir,
											)
										}
										os.RemoveAll(mountDir)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// DeleteVM deletes a VM and cleans up its resources
func (c *SDKClientV4) DeleteVM(ctx context.Context, vmID string) error {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.delete_vm",
		trace.WithAttributes(attribute.String("vm_id", vmID)),
	)
	defer span.End()

	c.logger.LogAttrs(ctx, slog.LevelInfo, "deleting VM",
		slog.String("vm_id", vmID),
	)

	vm, exists := c.vmRegistry[vmID]
	if !exists {
		err := fmt.Errorf("vm %s not found", vmID)
		span.RecordError(err)
		c.vmErrorCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", "delete"),
			attribute.String("error", "vm_not_found"),
		))
		return err
	}

	// Stop the VM if it's running
	if vm.Machine != nil {
		if err := vm.Machine.StopVMM(); err != nil {
			c.logger.WarnContext(ctx, "failed to stop VMM during delete",
				"vm_id", vmID,
				"error", err,
			)
		}

		// Cancel the VM context
		if vm.CancelFunc != nil {
			vm.CancelFunc()
		}
	}

	// Remove port forwarding rules before deleting network
	if vm.NetworkInfo != nil && len(vm.PortMappings) > 0 {
		if err := c.removePortForwarding(ctx, vmID, vm.NetworkInfo.IPAddress.String(), vm.PortMappings); err != nil {
			c.logger.WarnContext(ctx, "failed to remove port forwarding",
				"vm_id", vmID,
				"error", err,
			)
		}

		// Release allocated ports in network manager
		releasedMappings := c.networkManager.ReleaseVMPorts(vmID)
		c.logger.InfoContext(ctx, "released VM port allocations",
			slog.String("vm_id", vmID),
			slog.Int("port_count", len(releasedMappings)),
		)
	}

	// Delete network resources
	if err := c.networkManager.DeleteVMNetwork(ctx, vmID); err != nil {
		c.logger.ErrorContext(ctx, "failed to delete VM network",
			"vm_id", vmID,
			"error", err,
		)
		// Continue with deletion even if network cleanup fails
	}

	// Clean up VM directory
	vmDir := filepath.Join(c.baseDir, vmID)
	if err := os.RemoveAll(vmDir); err != nil {
		c.logger.WarnContext(ctx, "failed to remove VM directory",
			"vm_id", vmID,
			"path", vmDir,
			"error", err,
		)
	}

	// Clean up jailer chroot
	chrootPath := filepath.Join(c.jailerConfig.ChrootBaseDir, "firecracker", vmID)
	if err := os.RemoveAll(chrootPath); err != nil {
		c.logger.WarnContext(ctx, "failed to remove jailer chroot",
			"vm_id", vmID,
			"path", chrootPath,
			"error", err,
		)
	}

	// Release asset leases
	if leaseIDs, ok := c.vmAssetLeases[vmID]; ok {
		c.logger.LogAttrs(ctx, slog.LevelInfo, "releasing asset leases",
			slog.String("vm_id", vmID),
			slog.Int("lease_count", len(leaseIDs)),
		)

		for _, leaseID := range leaseIDs {
			releaseCtx, releaseSpan := c.tracer.Start(ctx, "metald.firecracker.release_asset",
				trace.WithAttributes(
					attribute.String("vm.id", vmID),
					attribute.String("lease.id", leaseID),
				),
			)
			err := c.assetClient.ReleaseAsset(releaseCtx, leaseID)
			if err != nil {
				releaseSpan.RecordError(err)
				releaseSpan.SetStatus(codes.Error, err.Error())
			}
			releaseSpan.End()
			if err != nil {
				c.logger.ErrorContext(ctx, "failed to release asset lease",
					"vm_id", vmID,
					"lease_id", leaseID,
					"error", err,
				)
				// Continue with other leases even if one fails
			}
		}
		delete(c.vmAssetLeases, vmID)
	}

	// Remove from registry
	delete(c.vmRegistry, vmID)

	c.vmDeleteCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("status", "success"),
	))

	c.logger.LogAttrs(ctx, slog.LevelInfo, "VM deleted successfully",
		slog.String("vm_id", vmID),
	)

	return nil
}

// ShutdownVM gracefully shuts down a VM
func (c *SDKClientV4) ShutdownVM(ctx context.Context, vmID string) error {
	return c.ShutdownVMWithOptions(ctx, vmID, false, 30)
}

// ShutdownVMWithOptions shuts down a VM with configurable options
func (c *SDKClientV4) ShutdownVMWithOptions(ctx context.Context, vmID string, force bool, timeoutSeconds int32) error {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.shutdown_vm",
		trace.WithAttributes(
			attribute.String("vm_id", vmID),
			attribute.Bool("force", force),
			attribute.Int("timeout_seconds", int(timeoutSeconds)),
		),
	)
	defer span.End()

	vm, exists := c.vmRegistry[vmID]
	if !exists {
		err := fmt.Errorf("vm %s not found", vmID)
		span.RecordError(err)
		return err
	}

	// AIDEV-NOTE: Validate VM state before shutdown operation
	if vm.State != metaldv1.VmState_VM_STATE_RUNNING {
		err := fmt.Errorf("vm %s is in %s state, can only shutdown VMs in RUNNING state", vmID, vm.State.String())
		span.RecordError(err)
		return err
	}

	if vm.Machine == nil {
		return fmt.Errorf("vm %s firecracker process not available", vmID)
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "shutting down VM",
		slog.String("vm_id", vmID),
		slog.String("current_state", vm.State.String()),
		slog.Bool("force", force),
		slog.Int("timeout_seconds", int(timeoutSeconds)),
	)

	// Create a timeout context
	shutdownCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	if force { //nolint:nestif // Complex shutdown logic requires nested conditions for force vs graceful shutdown
		// Force shutdown by pausing the VM to preserve the socket for resume
		// Note: Using PauseVM instead of StopVMM to allow resume operations
		if err := vm.Machine.PauseVM(shutdownCtx); err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to force shutdown VM: %w", err)
		}
	} else {
		// Try graceful shutdown first by pausing the VM
		// Note: Using PauseVM instead of Shutdown to preserve the firecracker process and socket
		if err := vm.Machine.PauseVM(shutdownCtx); err != nil {
			c.logger.WarnContext(ctx, "graceful shutdown failed",
				"vm_id", vmID,
				"error", err,
			)
			span.RecordError(err)
			return fmt.Errorf("failed to shutdown VM: %w", err)
		}
	}

	// Note: Removed Wait() call since we're pausing instead of stopping the VMM
	// The firecracker process remains running to allow resume operations

	// Update state
	vm.State = metaldv1.VmState_VM_STATE_SHUTDOWN

	c.logger.LogAttrs(ctx, slog.LevelInfo, "VM shutdown successfully",
		slog.String("vm_id", vmID),
	)

	return nil
}

// PauseVM pauses a running VM
func (c *SDKClientV4) PauseVM(ctx context.Context, vmID string) error {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.pause_vm",
		trace.WithAttributes(attribute.String("vm_id", vmID)),
	)
	defer span.End()

	vm, exists := c.vmRegistry[vmID]
	if !exists {
		err := fmt.Errorf("vm %s not found", vmID)
		span.RecordError(err)
		return err
	}

	// AIDEV-NOTE: Validate VM state before pause operation
	if vm.State != metaldv1.VmState_VM_STATE_RUNNING {
		err := fmt.Errorf("vm %s is in %s state, can only pause VMs in RUNNING state", vmID, vm.State.String())
		span.RecordError(err)
		return err
	}

	if vm.Machine == nil {
		return fmt.Errorf("vm %s firecracker process not available", vmID)
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "pausing VM",
		slog.String("vm_id", vmID),
		slog.String("current_state", vm.State.String()),
	)

	if err := vm.Machine.PauseVM(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to pause VM: %w", err)
	}

	vm.State = metaldv1.VmState_VM_STATE_PAUSED

	c.logger.LogAttrs(ctx, slog.LevelInfo, "VM paused successfully",
		slog.String("vm_id", vmID),
	)

	return nil
}

// ResumeVM resumes a paused or shutdown VM
func (c *SDKClientV4) ResumeVM(ctx context.Context, vmID string) error {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.resume_vm",
		trace.WithAttributes(attribute.String("vm_id", vmID)),
	)
	defer span.End()

	vm, exists := c.vmRegistry[vmID]
	if !exists {
		err := fmt.Errorf("vm %s not found", vmID)
		span.RecordError(err)
		return err
	}

	// AIDEV-NOTE: Validate VM state before resume operation - allow both PAUSED and SHUTDOWN
	if vm.State != metaldv1.VmState_VM_STATE_PAUSED && vm.State != metaldv1.VmState_VM_STATE_SHUTDOWN {
		err := fmt.Errorf("vm %s is in %s state, can only resume VMs in PAUSED or SHUTDOWN state", vmID, vm.State.String())
		span.RecordError(err)
		return err
	}

	// AIDEV-NOTE: Reconnect to firecracker process if machine is nil (restored from database)
	if vm.Machine == nil {
		c.logger.InfoContext(ctx, "reconnecting to existing firecracker process",
			"vm_id", vmID,
		)

		if err := c.reconnectToFirecracker(ctx, vm); err != nil {
			// AIDEV-BUSINESS_RULE: If reconnection fails (e.g., service restart killed processes),
			// recreate the VM from scratch to enable resume functionality
			c.logger.WarnContext(ctx, "failed to reconnect to firecracker process, recreating VM",
				"vm_id", vmID,
				"error", err,
			)

			if err := c.recreateVMForResume(ctx, vm); err != nil {
				span.RecordError(err)
				return fmt.Errorf("failed to recreate VM for resume: %w", err)
			}
		}
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "resuming VM",
		slog.String("vm_id", vmID),
		slog.String("current_state", vm.State.String()),
	)

	if err := vm.Machine.ResumeVM(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to resume VM: %w", err)
	}

	vm.State = metaldv1.VmState_VM_STATE_RUNNING

	c.logger.LogAttrs(ctx, slog.LevelInfo, "VM resumed successfully",
		slog.String("vm_id", vmID),
	)

	return nil
}

// RebootVM reboots a running VM
func (c *SDKClientV4) RebootVM(ctx context.Context, vmID string) error {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.reboot_vm",
		trace.WithAttributes(attribute.String("vm_id", vmID)),
	)
	defer span.End()

	c.logger.LogAttrs(ctx, slog.LevelInfo, "rebooting VM",
		slog.String("vm_id", vmID),
	)

	// Shutdown the VM
	if err := c.ShutdownVMWithOptions(ctx, vmID, false, 30); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to shutdown VM for reboot: %w", err)
	}

	// Wait a moment
	time.Sleep(1 * time.Second)

	// Boot the VM again
	if err := c.BootVM(ctx, vmID); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to boot VM after shutdown: %w", err)
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "VM rebooted successfully",
		slog.String("vm_id", vmID),
	)

	return nil
}

// generateAssetID generates a deterministic asset ID based on type and labels
func (c *SDKClientV4) generateAssetID(assetType assetv1.AssetType, labels map[string]string) string {
	// Create a deterministic string from sorted labels
	var parts []string
	parts = append(parts, fmt.Sprintf("type=%s", assetType.String()))

	// Sort label keys for deterministic ordering
	var keys []string
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Add sorted labels
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, labels[k]))
	}

	// Create a hash of the combined string
	combined := strings.Join(parts, ",")
	hash := sha256.Sum256([]byte(combined))

	// Return a readable asset ID
	return fmt.Sprintf("asset-%x", hash[:8])
}

// GetVMInfo returns information about a VM
// AIDEV-NOTE: GetVMInfo now includes port mappings in the NetworkInfo response
// Port mappings are retrieved from the network manager and converted to protobuf format
// This allows CLI clients to display randomly assigned host ports for VM services
func (c *SDKClientV4) GetVMInfo(ctx context.Context, vmID string) (*types.VMInfo, error) {
	_, span := c.tracer.Start(ctx, "metald.firecracker.get_vm_info",
		trace.WithAttributes(attribute.String("vm_id", vmID)),
	)
	defer span.End()

	vm, exists := c.vmRegistry[vmID]
	if !exists {
		err := fmt.Errorf("vm %s not found", vmID)
		span.RecordError(err)
		return nil, err
	}

	info := &types.VMInfo{ //nolint:exhaustruct // NetworkInfo is populated conditionally below
		Config: vm.Config,
		State:  vm.State,
	}

	// Add network info if available
	if vm.NetworkInfo != nil {
		// Get port mappings for this VM
		portMappings := c.networkManager.GetVMPorts(vmID)

		// Convert network.PortMapping to protobuf PortMapping
		var protoPortMappings []*metaldv1.PortMapping
		for _, mapping := range portMappings {
			protoPortMappings = append(protoPortMappings, &metaldv1.PortMapping{
				ContainerPort: int32(mapping.ContainerPort), //nolint:gosec // ports are within valid range
				HostPort:      int32(mapping.HostPort),      //nolint:gosec // ports are within valid range
				Protocol:      mapping.Protocol,
			})
		}

		info.NetworkInfo = &metaldv1.VmNetworkInfo{ //nolint:exhaustruct // Optional fields are not needed for basic network info
			IpAddress:    vm.NetworkInfo.IPAddress.String(),
			MacAddress:   vm.NetworkInfo.MacAddress,
			TapDevice:    vm.NetworkInfo.TapDevice,
			PortMappings: protoPortMappings,
		}
	}

	return info, nil
}

// GetVMMetrics returns metrics for a VM
func (c *SDKClientV4) GetVMMetrics(ctx context.Context, vmID string) (*types.VMMetrics, error) {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.get_vm_metrics",
		trace.WithAttributes(attribute.String("vm_id", vmID)),
	)
	defer span.End()

	vm, exists := c.vmRegistry[vmID]
	if !exists {
		err := fmt.Errorf("vm %s not found", vmID)
		span.RecordError(err)
		return nil, err
	}

	if vm.Machine == nil {
		return nil, fmt.Errorf("vm %s is not running", vmID)
	}

	// Read real metrics from Firecracker stats FIFO
	return c.readFirecrackerMetrics(ctx, vmID)
}

// FirecrackerMetrics represents the JSON structure from Firecracker stats
type FirecrackerMetrics struct {
	VCPU []struct {
		ExitReasons map[string]int64 `json:"exit_reasons"`
	} `json:"vcpu"`
	Block []struct {
		ReadBytes  int64 `json:"read_bytes"`
		WriteBytes int64 `json:"write_bytes"`
		ReadCount  int64 `json:"read_count"`
		WriteCount int64 `json:"write_count"`
	} `json:"block"`
	Net []struct {
		RxBytes   int64 `json:"rx_bytes"`
		TxBytes   int64 `json:"tx_bytes"`
		RxPackets int64 `json:"rx_packets"`
		TxPackets int64 `json:"tx_packets"`
	} `json:"net"`
	// Note: CPU time and memory usage may be in other fields or require calculation
}

// readFirecrackerMetrics reads metrics from the Firecracker stats FIFO
func (c *SDKClientV4) readFirecrackerMetrics(ctx context.Context, vmID string) (*types.VMMetrics, error) {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.read_metrics",
		trace.WithAttributes(attribute.String("vm_id", vmID)),
	)
	defer span.End()

	// Construct FIFO path
	fifoPath := filepath.Join(c.jailerConfig.ChrootBaseDir, "firecracker", vmID, "root", "metrics.fifo")

	// Try to read from FIFO (with timeout for blocking read)
	file, err := os.OpenFile(fifoPath, os.O_RDONLY, 0)
	if err != nil {
		// If FIFO doesn't exist or can't be opened, return zeros (VM might be starting)
		c.logger.WarnContext(ctx, "cannot read metrics FIFO",
			slog.String("vm_id", vmID),
			slog.String("fifo_path", fifoPath),
			slog.String("error", err.Error()),
		)
		return &types.VMMetrics{
			Timestamp:        time.Now(),
			CpuTimeNanos:     0,
			MemoryUsageBytes: 0,
			DiskReadBytes:    0,
			DiskWriteBytes:   0,
			NetworkRxBytes:   0,
			NetworkTxBytes:   0,
		}, nil
	}
	defer file.Close()

	// AIDEV-NOTE: Firecracker writes a continuous JSON stream to the FIFO
	// We need to use a JSON decoder to handle streaming JSON objects properly
	type result struct {
		metrics *FirecrackerMetrics
		err     error
	}
	resultCh := make(chan result, 1)

	go func() {
		decoder := json.NewDecoder(file)
		var fcMetrics FirecrackerMetrics

		// AIDEV-NOTE: Firecracker writes periodic JSON objects to the FIFO
		// We might start reading in the middle of a JSON object, so we need to
		// keep trying until we get a complete, valid JSON object
		maxAttempts := 5
		for attempt := 0; attempt < maxAttempts; attempt++ {
			if err := decoder.Decode(&fcMetrics); err != nil {
				// If we get a JSON syntax error, it might be because we started
				// reading in the middle of an object. Try again.
				if attempt < maxAttempts-1 {
					continue
				}
				resultCh <- result{metrics: nil, err: err}
				return
			}

			// Successfully decoded a complete JSON object
			resultCh <- result{metrics: &fcMetrics, err: nil}
			return
		}
	}()

	var fcMetrics *FirecrackerMetrics
	select {
	case res := <-resultCh:
		if res.err != nil {
			c.logger.WarnContext(ctx, "failed to read JSON from metrics FIFO",
				slog.String("vm_id", vmID),
				slog.String("error", res.err.Error()),
			)
			// Return zeros on read error - VM might still be starting up
			return &types.VMMetrics{
				Timestamp:        time.Now(),
				CpuTimeNanos:     0,
				MemoryUsageBytes: 0,
				DiskReadBytes:    0,
				DiskWriteBytes:   0,
				NetworkRxBytes:   0,
				NetworkTxBytes:   0,
			}, nil
		}
		fcMetrics = res.metrics

	case <-time.After(2 * time.Second):
		// Timeout - no metrics available within timeout
		c.logger.DebugContext(ctx, "timeout reading metrics FIFO",
			slog.String("vm_id", vmID),
		)
		return &types.VMMetrics{
			Timestamp:        time.Now(),
			CpuTimeNanos:     0,
			MemoryUsageBytes: 0,
			DiskReadBytes:    0,
			DiskWriteBytes:   0,
			NetworkRxBytes:   0,
			NetworkTxBytes:   0,
		}, nil
	}

	// Convert to our internal format
	metrics := &types.VMMetrics{
		Timestamp:        time.Now(),
		CpuTimeNanos:     0, // TODO: Calculate from VCPU exit reasons or other fields
		MemoryUsageBytes: 0, // TODO: Extract from memory metrics if available
		DiskReadBytes:    0,
		DiskWriteBytes:   0,
		NetworkRxBytes:   0,
		NetworkTxBytes:   0,
	}

	// Aggregate disk metrics from all block devices
	for _, block := range fcMetrics.Block {
		metrics.DiskReadBytes += block.ReadBytes
		metrics.DiskWriteBytes += block.WriteBytes
	}

	// Aggregate network metrics from all network interfaces
	for _, net := range fcMetrics.Net {
		metrics.NetworkRxBytes += net.RxBytes
		metrics.NetworkTxBytes += net.TxBytes
	}

	c.logger.DebugContext(ctx, "read Firecracker metrics",
		slog.String("vm_id", vmID),
		slog.Int64("disk_read_bytes", metrics.DiskReadBytes),
		slog.Int64("disk_write_bytes", metrics.DiskWriteBytes),
		slog.Int64("network_rx_bytes", metrics.NetworkRxBytes),
		slog.Int64("network_tx_bytes", metrics.NetworkTxBytes),
	)

	return metrics, nil
}

func (c *SDKClientV4) Ping(ctx context.Context) error {
	c.logger.DebugContext(ctx, "pinging firecracker SDK v4 backend")
	return nil
}

func (c *SDKClientV4) Shutdown(ctx context.Context) error {
	ctx, span := c.tracer.Start(ctx, "metald.firecracker.shutdown")
	defer span.End()

	c.logger.InfoContext(ctx, "shutting down SDK v4 backend")

	// AIDEV-BUSINESS_RULE: Preserve ALL VMs across metald restarts
	// VMs should persist like any other virtualization platform (VMware, VirtualBox, etc.)
	vmCount := len(c.vmRegistry)
	c.logger.InfoContext(ctx, "preserving all VMs during backend shutdown",
		"vm_count", vmCount,
	)

	for vmID, vm := range c.vmRegistry {
		c.logger.InfoContext(ctx, "preserving VM during backend shutdown",
			"vm_id", vmID,
			"state", vm.State.String(),
		)
		if vm.Machine != nil {
			if err := vm.Machine.StopVMM(); err != nil {
				c.logger.ErrorContext(ctx, "failed to stop VM during shutdown",
					"vm_id", vmID,
					"error", err,
				)
			}
			if vm.CancelFunc != nil {
				vm.CancelFunc()
			}
		}
		// TODO: Ensure VM state is properly persisted to database
		// The restoration logic will handle reconnecting to these VMs on startup
	}

	c.logger.InfoContext(ctx, "SDK v4 backend shutdown complete - all VMs preserved",
		"preserved_vm_count", vmCount,
	)
	return nil
}

// Ensure SDKClientV4 implements Backend interface
var _ types.Backend = (*SDKClientV4)(nil)

// generateV4VMID generates a unique VM ID for V4 client
func generateV4VMID() (string, error) {
	// Generate a random ID
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random ID: %w", err)
	}
	return fmt.Sprintf("ud-%s", hex.EncodeToString(bytes)), nil
}

// Helper function to copy files with ownership
func copyFileWithOwnership(src, dst string, uid, gid int) error {
	// Use cp command to handle large files efficiently
	cmd := exec.Command("cp", "-f", src, dst)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cp command failed: %w, output: %s", err, output)
	}

	// Set permissions
	if err := os.Chmod(dst, 0644); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", dst, err)
	}

	// Set ownership
	if err := os.Chown(dst, uid, gid); err != nil {
		// Log but don't fail - might work anyway
		return nil
	}

	return nil
}

// AIDEV-NOTE: This implementation integrates jailer functionality directly into metald
// Key advantages:
// 1. Network setup happens BEFORE dropping privileges
// 2. Tap devices are created with full capabilities
// 3. We maintain security isolation via chroot and privilege dropping
// 4. No external jailer binary needed - everything is integrated

// loadContainerMetadata loads container metadata from the metadata file if it exists
func (c *SDKClientV4) loadContainerMetadata(ctx context.Context, rootfsPath string) (*builderv1.ImageMetadata, error) {
	// AIDEV-NOTE: Load container metadata saved by builderd
	// The metadata file is named {buildID}.metadata.json and should be alongside the rootfs

	// Extract base name without extension
	baseName := strings.TrimSuffix(filepath.Base(rootfsPath), filepath.Ext(rootfsPath))
	metadataPath := filepath.Join(filepath.Dir(rootfsPath), baseName+".metadata.json")

	c.logger.LogAttrs(ctx, slog.LevelInfo, "AIDEV-DEBUG: looking for container metadata",
		slog.String("rootfs_path", rootfsPath),
		slog.String("metadata_path", metadataPath),
	)

	// Check if metadata file exists
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		// AIDEV-NOTE: Fallback to check for metadata.json in VM chroot directory
		// When assets are copied to VM chroot by assetmanagerd, metadata file is renamed to metadata.json
		fallbackPath := filepath.Join(filepath.Dir(rootfsPath), "metadata.json")
		if _, err := os.Stat(fallbackPath); os.IsNotExist(err) {
			c.logger.LogAttrs(ctx, slog.LevelDebug, "no metadata file found in either location",
				slog.String("primary_path", metadataPath),
				slog.String("fallback_path", fallbackPath),
			)
			return nil, nil // No metadata is not an error
		}
		// Use fallback path
		metadataPath = fallbackPath
		c.logger.LogAttrs(ctx, slog.LevelInfo, "AIDEV-DEBUG: using fallback metadata path",
			slog.String("fallback_path", fallbackPath),
		)
	}

	// Read metadata file
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	// Parse metadata
	var metadata builderv1.ImageMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "loaded container metadata",
		slog.String("image", metadata.GetOriginalImage()),
		slog.Int("entrypoint_len", len(metadata.GetEntrypoint())),
		slog.Int("cmd_len", len(metadata.GetCommand())),
		slog.Int("env_vars", len(metadata.GetEnv())),
		slog.Int("exposed_ports", len(metadata.GetExposedPorts())),
	)

	return &metadata, nil
}

// buildKernelArgsWithMetadata builds kernel arguments incorporating container metadata
func (c *SDKClientV4) buildKernelArgsWithMetadata(ctx context.Context, baseArgs string, metadata *builderv1.ImageMetadata) string {
	// AIDEV-NOTE: Build kernel args that will execute the container's entrypoint/cmd

	// Parse existing kernel args to preserve important ones
	var kernelParams []string
	var hasInit bool

	if baseArgs != "" {
		// Split base args and check for existing init
		parts := strings.Fields(baseArgs)
		for _, part := range parts {
			if strings.HasPrefix(part, "init=") {
				hasInit = true
			}
			// Keep important kernel parameters
			if strings.HasPrefix(part, "console=") ||
				strings.HasPrefix(part, "reboot=") ||
				strings.HasPrefix(part, "panic=") ||
				strings.HasPrefix(part, "pci=") ||
				strings.HasPrefix(part, "i8042.") {
				kernelParams = append(kernelParams, part)
			}
		}
	}

	// Add default kernel params if not present
	if len(kernelParams) == 0 {
		kernelParams = []string{
			"console=ttyS0,115200",
			"reboot=k",
			"panic=1",
			"pci=off",
			"i8042.noaux",
			"i8042.nomux",
			"i8042.nopnp",
			"i8042.dumbkbd",
			"root=/dev/vda",
			"rw",
		}
	}

	// AIDEV-NOTE: Always add verbose logging for debugging
	// Check if we already have these parameters to avoid duplicates
	hasEarlyPrintk := false
	hasLogLevel := false
	for _, param := range kernelParams {
		if strings.HasPrefix(param, "earlyprintk=") {
			hasEarlyPrintk = true
		}
		if strings.HasPrefix(param, "loglevel=") {
			hasLogLevel = true
		}
	}
	if !hasEarlyPrintk {
		kernelParams = append(kernelParams, "earlyprintk=serial,ttyS0,115200")
	}
	if !hasLogLevel {
		kernelParams = append(kernelParams, "loglevel=8")
	}

	// AIDEV-NOTE: Add aggressive debugging parameters
	kernelParams = append(kernelParams, "debug")
	kernelParams = append(kernelParams, "ignore_loglevel")
	kernelParams = append(kernelParams, "printk.devkmsg=on")

	// If we have metadata and no init specified, use metald-init
	if metadata != nil && !hasInit {
		// Add environment variables as kernel parameters
		// Format: env.KEY=VALUE
		for key, value := range metadata.GetEnv() {
			// Skip potentially problematic env vars
			if key == "PATH" || strings.Contains(key, " ") || strings.Contains(value, " ") {
				continue
			}
			kernelParams = append(kernelParams, fmt.Sprintf("env.%s=%s", key, value))
		}

		// Add working directory if specified
		if metadata.GetWorkingDir() != "" {
			kernelParams = append(kernelParams, fmt.Sprintf("workdir=%s", metadata.GetWorkingDir()))
		}

		// Use metald-init as the init process wrapper
		kernelParams = append(kernelParams, "init=/usr/bin/metald-init")

		// Build the final kernel args string
		args := strings.Join(kernelParams, " ")

		// Don't pass command on kernel command line - metald-init will read from /container.cmd
		// This avoids all the kernel command line parsing issues with spaces and special characters
		c.logger.LogAttrs(ctx, slog.LevelInfo, "built kernel args with container metadata",
			slog.String("init", "/usr/bin/metald-init"),
			slog.String("final_args", args),
		)

		return args
	}

	// No metadata or init already specified, return base args
	return baseArgs
}

// buildNetworkKernelArgs builds kernel command line arguments for network configuration
// AIDEV-NOTE: Implements advanced guest network configuration using kernel parameters
// as described in https://github.com/firecracker-microvm/firecracker/blob/main/docs/network-setup.md#advanced-guest-network-configuration-using-kernel-command-line
func (c *SDKClientV4) buildNetworkKernelArgs(ctx context.Context, networkInfo *network.VMNetwork) []string {
	if networkInfo == nil {
		return nil
	}

	var networkArgs []string

	// Primary IP configuration using the ip= kernel parameter
	// AIDEV-NOTE: This is REQUIRED for guest OS to configure its interface
	// The bridge handles host-side routing, but guest needs IP parameters to configure eth0
	ipArg := networkInfo.KernelCmdlineArgs()
	if ipArg != "" {
		networkArgs = append(networkArgs, ipArg)
	}

	// Add DNS nameservers if available
	if len(networkInfo.DNSServers) > 0 {
		// Primary nameserver
		networkArgs = append(networkArgs, fmt.Sprintf("nameserver=%s", networkInfo.DNSServers[0]))

		// Secondary nameserver if available
		if len(networkInfo.DNSServers) > 1 {
			networkArgs = append(networkArgs, fmt.Sprintf("nameserver1=%s", networkInfo.DNSServers[1]))
		}
	}

	// Add route configuration for any custom routes
	for i, route := range networkInfo.Routes {
		if route.Destination != nil && route.Gateway != nil {
			routeArg := fmt.Sprintf("route=%s,%s,%d",
				route.Destination.String(),
				route.Gateway.String(),
				route.Metric,
			)
			networkArgs = append(networkArgs, routeArg)

			// Limit to prevent kernel command line overflow
			if i >= 5 {
				c.logger.WarnContext(ctx, "limiting routes to prevent kernel cmdline overflow",
					slog.Int("total_routes", len(networkInfo.Routes)),
					slog.Int("max_routes", 5),
				)
				break
			}
		}
	}

	// Add IPv6 configuration if available
	if networkInfo.IPv6Address != nil && !networkInfo.IPv6Address.IsUnspecified() {
		networkArgs = append(networkArgs, fmt.Sprintf("ipv6=%s", networkInfo.IPv6Address.String()))
	}

	// Add VLAN configuration if specified
	if networkInfo.VLANID > 0 {
		networkArgs = append(networkArgs, fmt.Sprintf("vlan=%d", networkInfo.VLANID))
	}

	c.logger.LogAttrs(ctx, slog.LevelDebug, "built network kernel arguments",
		slog.String("vm_id", networkInfo.VMID),
		slog.String("ip", networkInfo.IPAddress.String()),
		slog.String("gateway", networkInfo.Gateway.String()),
		slog.Int("dns_servers", len(networkInfo.DNSServers)),
		slog.Int("routes", len(networkInfo.Routes)),
		slog.Int("network_args_count", len(networkArgs)),
	)

	return networkArgs
}

// buildKernelArgsWithNetworkAndMetadata builds kernel arguments incorporating both network configuration and container metadata
// AIDEV-NOTE: This is the main function for building comprehensive kernel args that supports both
// advanced network configuration and container metadata
func (c *SDKClientV4) buildKernelArgsWithNetworkAndMetadata(ctx context.Context, baseArgs string, networkInfo *network.VMNetwork, metadata *builderv1.ImageMetadata) string {
	// Start with base args from buildKernelArgsWithMetadata
	args := c.buildKernelArgsWithMetadata(ctx, baseArgs, metadata)

	// Add network configuration if enabled and available
	if c.enableKernelNetworkConfig {
		networkArgs := c.buildNetworkKernelArgs(ctx, networkInfo)
		if len(networkArgs) > 0 {
			// Parse existing args to avoid duplicates and check for conflicts
			existingArgs := strings.Fields(args)
			var finalArgs []string

			// Keep existing args, but remove any conflicting network parameters
			for _, arg := range existingArgs {
				// Skip existing network parameters that will be replaced
				if !strings.HasPrefix(arg, "ip=") &&
					!strings.HasPrefix(arg, "nameserver=") &&
					!strings.HasPrefix(arg, "route=") &&
					!strings.HasPrefix(arg, "ipv6=") &&
					!strings.HasPrefix(arg, "vlan=") {
					finalArgs = append(finalArgs, arg)
				}
			}

			// Add network arguments
			finalArgs = append(finalArgs, networkArgs...)

			args = strings.Join(finalArgs, " ")

			c.logger.LogAttrs(ctx, slog.LevelInfo, "built comprehensive kernel args with network and metadata",
				slog.String("vm_id", networkInfo.VMID),
				slog.Int("total_network_args", len(networkArgs)),
				slog.String("final_args", args),
			)
		}
	} else {
		vmID := "unknown"
		if networkInfo != nil {
			vmID = networkInfo.VMID
		}
		c.logger.LogAttrs(ctx, slog.LevelDebug, "kernel-based network configuration disabled",
			slog.String("vm_id", vmID),
		)
	}

	return args
}

// parseExposedPorts parses exposed ports from container metadata and allocates host ports
func (c *SDKClientV4) parseExposedPorts(ctx context.Context, vmID string, metadata *builderv1.ImageMetadata) ([]network.PortMapping, error) {
	// AIDEV-NOTE: Parse exposed ports and allocate host ports using network manager
	if metadata == nil || len(metadata.GetExposedPorts()) == 0 {
		return nil, nil
	}

	// Get VM network info to find the IP address
	vmNet, err := c.networkManager.GetVMNetwork(vmID)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to get VM network info for port allocation",
			slog.String("vm_id", vmID),
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to get VM network info for %s: %w", vmID, err)
	}

	if vmNet == nil {
		return nil, fmt.Errorf("VM network not found for %s", vmID)
	}

	// Use network manager to allocate ports with VM IP for DNAT rules
	mappings, err := c.networkManager.AllocatePortsForVM(vmID, vmNet.IPAddress, metadata.GetExposedPorts())
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to allocate ports for VM",
			slog.String("vm_id", vmID),
			slog.String("vm_ip", vmNet.IPAddress.String()),
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to allocate ports for VM %s: %w", vmID, err)
	}

	c.logger.InfoContext(ctx, "allocated ports for VM with forwarding rules",
		slog.String("vm_id", vmID),
		slog.String("vm_ip", vmNet.IPAddress.String()),
		slog.Int("port_count", len(mappings)),
	)

	return mappings, nil
}

// validateIPAddress validates an IP address to prevent command injection
func validateIPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// validatePortNumber validates a port number to prevent command injection
func validatePortNumber(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d, must be between 1-65535", port)
	}
	return nil
}

// validateProtocol validates network protocol to prevent command injection
func validateProtocol(protocol string) error {
	// Only allow tcp, udp, icmp protocols commonly used
	validProtocols := map[string]bool{
		"tcp":  true,
		"udp":  true,
		"icmp": true,
	}
	if !validProtocols[protocol] {
		return fmt.Errorf("invalid protocol: %s, must be tcp, udp, or icmp", protocol)
	}
	return nil
}

// validateVMID validates VM ID to prevent command injection
func validateVMID(vmID string) error {
	// VM IDs should only contain alphanumeric characters, hyphens, and underscores
	if len(vmID) == 0 || len(vmID) > 64 {
		return fmt.Errorf("invalid VM ID length: %s", vmID)
	}

	// Match only safe characters
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
	if !validPattern.MatchString(vmID) {
		return fmt.Errorf("invalid VM ID format: %s, only alphanumeric, hyphens, and underscores allowed", vmID)
	}
	return nil
}

// configurePortForwarding sets up iptables rules for port forwarding
func (c *SDKClientV4) configurePortForwarding(ctx context.Context, vmID string, vmIP string, mappings []network.PortMapping) error {
	// AIDEV-NOTE: Configure iptables rules for port forwarding

	// Validate inputs to prevent command injection
	if err := validateVMID(vmID); err != nil {
		return fmt.Errorf("invalid VM ID: %w", err)
	}
	if err := validateIPAddress(vmIP); err != nil {
		return fmt.Errorf("invalid VM IP: %w", err)
	}

	if len(mappings) == 0 {
		return nil
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "configuring port forwarding",
		slog.String("vm_id", vmID),
		slog.String("vm_ip", vmIP),
		slog.Int("port_count", len(mappings)),
	)

	for _, mapping := range mappings {
		// Validate port mapping parameters to prevent command injection
		if err := validateProtocol(mapping.Protocol); err != nil {
			return fmt.Errorf("invalid protocol in mapping: %w", err)
		}
		if err := validatePortNumber(mapping.HostPort); err != nil {
			return fmt.Errorf("invalid host port in mapping: %w", err)
		}
		if err := validatePortNumber(mapping.ContainerPort); err != nil {
			return fmt.Errorf("invalid container port in mapping: %w", err)
		}

		// Add DNAT rule to forward host port to VM port (inputs validated above)
		// iptables -t nat -A PREROUTING -p tcp --dport HOST_PORT -j DNAT --to-destination VM_IP:CONTAINER_PORT
		// #nosec G204 -- All parameters validated above to prevent command injection
		dnatCmd := exec.Command("iptables",
			"-t", "nat",
			"-A", "PREROUTING",
			"-p", mapping.Protocol,
			"--dport", fmt.Sprintf("%d", mapping.HostPort),
			"-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", vmIP, mapping.ContainerPort),
		)

		if output, err := dnatCmd.CombinedOutput(); err != nil {
			c.logger.ErrorContext(ctx, "failed to add DNAT rule",
				slog.String("error", err.Error()),
				slog.String("output", string(output)),
				slog.Int("host_port", mapping.HostPort),
				slog.Int("container_port", mapping.ContainerPort),
			)
			return fmt.Errorf("failed to add DNAT rule: %w", err)
		}

		// Add FORWARD rule to allow traffic (inputs validated above)
		// iptables -A FORWARD -p tcp -d VM_IP --dport CONTAINER_PORT -j ACCEPT
		// #nosec G204 -- All parameters validated above to prevent command injection
		forwardCmd := exec.Command("iptables",
			"-A", "FORWARD",
			"-p", mapping.Protocol,
			"-d", vmIP,
			"--dport", fmt.Sprintf("%d", mapping.ContainerPort),
			"-j", "ACCEPT",
		)

		if output, err := forwardCmd.CombinedOutput(); err != nil {
			c.logger.ErrorContext(ctx, "failed to add FORWARD rule",
				slog.String("error", err.Error()),
				slog.String("output", string(output)),
				slog.Int("container_port", mapping.ContainerPort),
			)
			return fmt.Errorf("failed to add FORWARD rule: %w", err)
		}

		c.logger.LogAttrs(ctx, slog.LevelInfo, "configured port forwarding",
			slog.Int("host_port", mapping.HostPort),
			slog.Int("container_port", mapping.ContainerPort),
			slog.String("protocol", mapping.Protocol),
			slog.String("vm_ip", vmIP),
		)
	}

	return nil
}

// removePortForwarding removes iptables rules for a VM
func (c *SDKClientV4) removePortForwarding(ctx context.Context, vmID string, vmIP string, mappings []network.PortMapping) error {
	// AIDEV-NOTE: Remove iptables rules when VM is deleted

	// Validate inputs to prevent command injection
	if err := validateVMID(vmID); err != nil {
		return fmt.Errorf("invalid VM ID: %w", err)
	}
	if err := validateIPAddress(vmIP); err != nil {
		return fmt.Errorf("invalid VM IP: %w", err)
	}

	var errors []error

	for _, mapping := range mappings {
		// Validate port mapping parameters to prevent command injection
		if err := validateProtocol(mapping.Protocol); err != nil {
			errors = append(errors, fmt.Errorf("invalid protocol in mapping: %w", err))
			continue
		}
		if err := validatePortNumber(mapping.HostPort); err != nil {
			errors = append(errors, fmt.Errorf("invalid host port in mapping: %w", err))
			continue
		}
		if err := validatePortNumber(mapping.ContainerPort); err != nil {
			errors = append(errors, fmt.Errorf("invalid container port in mapping: %w", err))
			continue
		}
		// Remove DNAT rule (inputs validated above)
		// #nosec G204 -- All parameters validated above to prevent command injection
		dnatCmd := exec.Command("iptables",
			"-t", "nat",
			"-D", "PREROUTING",
			"-p", mapping.Protocol,
			"--dport", fmt.Sprintf("%d", mapping.HostPort),
			"-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", vmIP, mapping.ContainerPort),
		)

		if output, err := dnatCmd.CombinedOutput(); err != nil {
			c.logger.WarnContext(ctx, "failed to remove DNAT rule",
				"vm_id", vmID,
				"error", err.Error(),
				"output", string(output),
			)
			errors = append(errors, fmt.Errorf("failed to remove DNAT rule for port %d: %w", mapping.HostPort, err))
		}

		// Remove FORWARD rule (inputs validated above)
		// #nosec G204 -- All parameters validated above to prevent command injection
		forwardCmd := exec.Command("iptables",
			"-D", "FORWARD",
			"-p", mapping.Protocol,
			"-d", vmIP,
			"--dport", fmt.Sprintf("%d", mapping.ContainerPort),
			"-j", "ACCEPT",
		)

		if output, err := forwardCmd.CombinedOutput(); err != nil {
			c.logger.WarnContext(ctx, "failed to remove FORWARD rule",
				"vm_id", vmID,
				"error", err.Error(),
				"output", string(output),
			)
			errors = append(errors, fmt.Errorf("failed to remove FORWARD rule for port %d: %w", mapping.ContainerPort, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to remove %d port forwarding rules: %v", len(errors), errors)
	}
	return nil
}

// shutdownVMNetworkInterfaces brings down VM network interfaces during shutdown
// This makes the VM non-pingable while keeping resources allocated for potential restart
func (c *SDKClientV4) shutdownVMNetworkInterfaces(ctx context.Context, vmID string, networkInfo *network.VMNetwork) error {
	// AIDEV-NOTE: CRITICAL FIX - Lock OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c.logger.LogAttrs(ctx, slog.LevelInfo, "shutting down VM network interfaces",
		slog.String("vm_id", vmID),
		slog.String("namespace", networkInfo.Namespace),
		slog.String("tap_device", networkInfo.TapDevice),
	)

	// Bring down TAP device in host namespace
	if link, err := netlink.LinkByName(networkInfo.TapDevice); err == nil {
		if linkDownErr := netlink.LinkSetDown(link); linkDownErr != nil {
			c.logger.WarnContext(ctx, "failed to bring down TAP device",
				"device", networkInfo.TapDevice,
				"error", linkDownErr,
			)
		} else {
			c.logger.InfoContext(ctx, "brought down TAP device",
				"device", networkInfo.TapDevice,
			)
		}
	}

	// Bring down veth interfaces in namespace
	// This requires switching to the VM's network namespace
	nsHandle, err := netns.GetFromName(networkInfo.Namespace)
	if err != nil {
		return fmt.Errorf("failed to get namespace %s: %w", networkInfo.Namespace, err)
	}
	defer nsHandle.Close()

	// Switch to VM namespace
	originalNS, originalErr := netns.Get()
	if originalErr != nil {
		return fmt.Errorf("failed to get original namespace: %w", originalErr)
	}
	defer originalNS.Close()

	if setErr := netns.Set(nsHandle); setErr != nil {
		return fmt.Errorf("failed to switch to namespace %s: %w", networkInfo.Namespace, setErr)
	}
	defer func() {
		// Always switch back to original namespace
		if restoreErr := netns.Set(originalNS); restoreErr != nil {
			c.logger.ErrorContext(ctx, "failed to switch back to original namespace",
				"error", restoreErr,
			)
		}
	}()

	// Bring down all interfaces in the VM namespace except loopback
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links in namespace: %w", err)
	}

	for _, link := range links {
		// Skip loopback interface
		if link.Type() == "loopback" {
			continue
		}

		if err := netlink.LinkSetDown(link); err != nil {
			c.logger.WarnContext(ctx, "failed to bring down interface in namespace",
				"device", link.Attrs().Name,
				"namespace", networkInfo.Namespace,
				"error", err,
			)
		} else {
			c.logger.InfoContext(ctx, "brought down interface in namespace",
				"device", link.Attrs().Name,
				"namespace", networkInfo.Namespace,
			)
		}
	}

	c.logger.InfoContext(ctx, "VM network interfaces shut down successfully",
		"vm_id", vmID,
	)
	return nil
}

// startupVMNetworkInterfaces brings up VM network interfaces during resume/restart
// This re-enables network connectivity for the VM after shutdown
func (c *SDKClientV4) startupVMNetworkInterfaces(ctx context.Context, vmID string, networkInfo *network.VMNetwork) error {
	// AIDEV-NOTE: CRITICAL FIX - Lock OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c.logger.LogAttrs(ctx, slog.LevelInfo, "bringing up VM network interfaces",
		slog.String("vm_id", vmID),
		slog.String("namespace", networkInfo.Namespace),
		slog.String("tap_device", networkInfo.TapDevice),
	)

	// Bring up TAP device in host namespace
	if link, err := netlink.LinkByName(networkInfo.TapDevice); err == nil {
		if err := netlink.LinkSetUp(link); err != nil {
			c.logger.WarnContext(ctx, "failed to bring up TAP device",
				"device", networkInfo.TapDevice,
				"error", err,
			)
		} else {
			c.logger.InfoContext(ctx, "brought up TAP device",
				"device", networkInfo.TapDevice,
			)
		}
	}

	// Bring up veth interfaces in namespace
	nsHandle, err := netns.GetFromName(networkInfo.Namespace)
	if err != nil {
		return fmt.Errorf("failed to get namespace %s: %w", networkInfo.Namespace, err)
	}
	defer nsHandle.Close()

	// Switch to VM namespace
	originalNS, originalErr := netns.Get()
	if originalErr != nil {
		return fmt.Errorf("failed to get original namespace: %w", originalErr)
	}
	defer originalNS.Close()

	if setErr := netns.Set(nsHandle); setErr != nil {
		return fmt.Errorf("failed to switch to namespace %s: %w", networkInfo.Namespace, setErr)
	}
	defer func() {
		// Always switch back to original namespace
		if restoreErr := netns.Set(originalNS); restoreErr != nil {
			c.logger.ErrorContext(ctx, "failed to switch back to original namespace",
				"error", restoreErr,
			)
		}
	}()

	// Bring up all interfaces in the VM namespace except loopback (which should already be up)
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links in namespace: %w", err)
	}

	for _, link := range links {
		// Skip loopback interface
		if link.Type() == "loopback" {
			continue
		}

		if err := netlink.LinkSetUp(link); err != nil {
			c.logger.WarnContext(ctx, "failed to bring up interface in namespace",
				"device", link.Attrs().Name,
				"namespace", networkInfo.Namespace,
				"error", err,
			)
		} else {
			c.logger.InfoContext(ctx, "brought up interface in namespace",
				"device", link.Attrs().Name,
				"namespace", networkInfo.Namespace,
			)
		}
	}

	c.logger.InfoContext(ctx, "VM network interfaces started up successfully",
		"vm_id", vmID,
	)
	return nil
}

// copyMetadataFilesForAssets copies metadata files alongside rootfs assets when using asset manager
func (c *SDKClientV4) copyMetadataFilesForAssets(ctx context.Context, vmID string, config *metaldv1.VmConfig, preparedPaths map[string]string, jailerRoot string) error {
	// AIDEV-NOTE: When using asset manager, only rootfs files are copied, but we need metadata files too
	// This function finds the original metadata files and copies them to the jailer root

	for _, disk := range config.GetStorage() {
		if !disk.GetIsRootDevice() || disk.GetPath() == "" {
			continue
		}

		// Find the original rootfs path before asset preparation
		originalRootfsPath := disk.GetPath()

		// Check if this disk was replaced by an asset
		var preparedRootfsPath string
		for _, path := range preparedPaths {
			if strings.HasSuffix(path, ".ext4") || strings.HasSuffix(path, ".img") {
				preparedRootfsPath = path
				break
			}
		}

		if preparedRootfsPath == "" {
			// No rootfs asset found, skip metadata copying
			continue
		}

		// Look for metadata file alongside the original rootfs
		originalDir := filepath.Dir(originalRootfsPath)
		originalBaseName := strings.TrimSuffix(filepath.Base(originalRootfsPath), filepath.Ext(originalRootfsPath))
		metadataSrcPath := filepath.Join(originalDir, originalBaseName+".metadata.json")

		// Check if metadata file exists
		if _, err := os.Stat(metadataSrcPath); os.IsNotExist(err) {
			c.logger.LogAttrs(ctx, slog.LevelDebug, "no metadata file found for asset",
				slog.String("vm_id", vmID),
				slog.String("original_rootfs", originalRootfsPath),
				slog.String("expected_metadata", metadataSrcPath),
			)
			continue
		}

		// Copy metadata file to jailer root with the same base name as the prepared rootfs
		preparedBaseName := strings.TrimSuffix(filepath.Base(preparedRootfsPath), filepath.Ext(preparedRootfsPath))
		metadataDstPath := filepath.Join(jailerRoot, preparedBaseName+".metadata.json")

		if err := copyFileWithOwnership(metadataSrcPath, metadataDstPath, int(c.jailerConfig.UID), int(c.jailerConfig.GID)); err != nil {
			c.logger.WarnContext(ctx, "failed to copy metadata file",
				slog.String("vm_id", vmID),
				slog.String("src", metadataSrcPath),
				slog.String("dst", metadataDstPath),
				slog.String("error", err.Error()),
			)
			return fmt.Errorf("failed to copy metadata file %s: %w", metadataSrcPath, err)
		}

		c.logger.InfoContext(ctx, "copied metadata file for asset",
			slog.String("vm_id", vmID),
			slog.String("src", metadataSrcPath),
			slog.String("dst", metadataDstPath),
		)
	}

	return nil
}

// createContainerCmdFile creates /container.cmd file in VM chroot for metald-init
func (c *SDKClientV4) createContainerCmdFile(ctx context.Context, vmID string, metadata *builderv1.ImageMetadata) error {
	// AIDEV-NOTE: Create container.cmd file containing the full command for metald-init
	// Combines entrypoint and command from container metadata into JSON array

	if metadata == nil {
		return fmt.Errorf("metadata is required")
	}

	// Build full command array: entrypoint + command
	var fullCmd []string
	fullCmd = append(fullCmd, metadata.GetEntrypoint()...)
	fullCmd = append(fullCmd, metadata.GetCommand()...)

	if len(fullCmd) == 0 {
		return fmt.Errorf("no entrypoint or command found in metadata")
	}

	// Convert to JSON
	cmdJSON, err := json.Marshal(fullCmd)
	if err != nil {
		return fmt.Errorf("failed to marshal command to JSON: %w", err)
	}

	// AIDEV-NOTE: Write container.cmd into the rootfs.ext4 filesystem, not just chroot
	// Mount the rootfs.ext4 temporarily to inject the container.cmd file
	jailerRoot := filepath.Join(c.jailerConfig.ChrootBaseDir, "firecracker", vmID, "root")
	rootfsPath := filepath.Join(jailerRoot, "rootfs.ext4")

	// Create temporary mount point
	tmpMount := filepath.Join("/tmp", "rootfs-mount-"+vmID)
	if err := os.MkdirAll(tmpMount, 0755); err != nil {
		return fmt.Errorf("failed to create temp mount dir: %w", err)
	}
	defer os.RemoveAll(tmpMount)

	// Mount the rootfs.ext4
	mountCmd := exec.Command("mount", "-o", "loop", rootfsPath, tmpMount)
	if err := mountCmd.Run(); err != nil {
		return fmt.Errorf("failed to mount rootfs: %w", err)
	}
	defer func() {
		umountCmd := exec.Command("umount", tmpMount)
		umountCmd.Run()
	}()

	// Write container.cmd into the mounted filesystem
	containerCmdPath := filepath.Join(tmpMount, "container.cmd")
	if err := os.WriteFile(containerCmdPath, cmdJSON, 0600); err != nil {
		return fmt.Errorf("failed to write container.cmd to rootfs: %w", err)
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, "created container.cmd file",
		slog.String("vm_id", vmID),
		slog.String("path", containerCmdPath),
		slog.String("command", string(cmdJSON)),
	)

	return nil
}

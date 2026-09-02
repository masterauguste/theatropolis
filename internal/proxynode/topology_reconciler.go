package proxynode

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	topologyReconcileDebounce = time.Second
	topologyReconcileRetry    = 5 * time.Second
	topologyReconcileBackstop = 30 * time.Second
)

// TopologyReconciler is the single retry loop for a saved desired topology
// that is newer than the applied topology. A reconnect notification is
// deliberately debounced: Connect queues the authoritative applied profile
// before invoking the notification, and the Deployer then waits for that
// profile deployment to become terminal before it can reserve the Agent for
// the desired topology. The periodic backstop also covers address changes and
// a master restart that do not produce a new reconnect notification.
type TopologyReconciler struct {
	deployer *Deployer
	logger   *slog.Logger

	once    sync.Once
	trigger chan struct{}
	// triggerRevision binds an explicit readiness event to the desired
	// revision that existed when the event occurred. Without this binding, a
	// delayed startup/reconnect signal could accidentally unblock a later
	// deterministic failure that it did not observe.
	triggerRevision atomic.Uint64
	debounce        time.Duration
	retry           time.Duration
	backstop        time.Duration
}

func NewTopologyReconciler(deployer *Deployer, logger *slog.Logger) *TopologyReconciler {
	if logger == nil {
		logger = slog.Default()
	}
	return &TopologyReconciler{
		deployer: deployer,
		logger:   logger,
		trigger:  make(chan struct{}, 1),
		debounce: topologyReconcileDebounce,
		retry:    topologyReconcileRetry,
		backstop: topologyReconcileBackstop,
	}
}

// Start begins one coalesced retry loop. It performs an immediate startup
// reconciliation so a desired revision persisted before a crash cannot wait
// forever for a new control-plane event.
func (r *TopologyReconciler) Start(ctx context.Context) {
	if r == nil || r.deployer == nil {
		return
	}
	r.once.Do(func() {
		initialRevision := r.deployer.store.Snapshot().Revision
		go r.loop(ctx, initialRevision)
	})
}

// Trigger schedules a debounced retry after Connect has queued its
// authoritative applied-profile replay. Repeated reconnects coalesce.
func (r *TopologyReconciler) Trigger() {
	if r == nil {
		return
	}
	r.triggerRevision.Store(r.deployer.store.Snapshot().Revision)
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

func (r *TopologyReconciler) loop(ctx context.Context, initialForceRevision uint64) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	forceRevision := initialForceRevision
	forcePending := true
	var observedRevision, blockedRevision uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.trigger:
			forceRevision = r.triggerRevision.Load()
			forcePending = true
			resetTopologyTimer(timer, r.debounce)
		case <-timer.C:
			state := r.deployer.store.Snapshot()
			if state.Revision != observedRevision {
				observedRevision = state.Revision
				blockedRevision = 0
			}
			current, exists := r.deployer.Current()
			if exists && current.topologyRevision == state.Revision &&
				current.Status == FleetDeploymentFailed {
				switch current.plane {
				case deploymentTopology:
					if !r.deployer.hasPendingTransaction() {
						blockedRevision = state.Revision
					}
				case deploymentRecovery:
					// A successful recovery clears the journal even though the
					// historical job remains Failed (the interrupted candidate
					// itself did fail). A retained journal means an Agent rejected
					// or could not complete rollback. Do not hammer that Agent on
					// the periodic retry loop; a reconnect/address event or an
					// explicit trigger may retry the same desired revision.
					if r.deployer.hasPendingTransaction() {
						blockedRevision = state.Revision
					}
				}
			}
			force := forcePending && forceRevision == state.Revision
			if force {
				blockedRevision = 0
			}
			shouldAttempt := state.Revision != state.AppliedRevision && blockedRevision != state.Revision
			if shouldAttempt {
				job, err := r.deployer.ReconcilePending()
				if err != nil && !errors.Is(err, ErrDeploymentActive) {
					r.logger.Warn("pending Proxy Node topology reconciliation deferred", "error", err)
					blockedRevision = state.Revision
				} else if err == nil && job.plane == deploymentTopology &&
					job.topologyRevision == state.Revision && job.Status == FleetDeploymentFailed {
					blockedRevision = state.Revision
				}
			}
			if force || (forcePending && forceRevision < state.Revision) {
				forcePending = false
			}
			state = r.deployer.store.Snapshot()
			delay := r.backstop
			if state.Revision != state.AppliedRevision && blockedRevision != state.Revision {
				delay = r.retry
			}
			resetTopologyTimer(timer, delay)
		}
	}
}

func resetTopologyTimer(timer *time.Timer, delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}

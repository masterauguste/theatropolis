package proxynode

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

const billingDeploymentRetry = 30 * time.Second

// BillingEnforcer runs UTC+8 end-of-day transitions and keeps retrying a
// security-relevant deployment while an entrance Agent is offline.
type BillingEnforcer struct {
	store    *Store
	deployer *Deployer
	logger   *slog.Logger
	now      func() time.Time
	ctx      context.Context

	mu               sync.Mutex
	requested        uint64
	running          bool
	refreshRequested uint64
	refreshRunning   bool
}

func NewBillingEnforcer(store *Store, deployer *Deployer, logger *slog.Logger) *BillingEnforcer {
	if logger == nil {
		logger = slog.Default()
	}
	return &BillingEnforcer{store: store, deployer: deployer, logger: logger, now: time.Now}
}

func (e *BillingEnforcer) Start(ctx context.Context) {
	e.mu.Lock()
	e.ctx = ctx
	e.mu.Unlock()
	go e.calendarLoop(ctx)
}

func (e *BillingEnforcer) TriggerDeployment() {
	e.mu.Lock()
	e.requested++
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	ctx := e.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	e.mu.Unlock()
	go e.deploymentLoop(ctx)
}

func (e *BillingEnforcer) TriggerAppliedRefresh() {
	e.mu.Lock()
	e.refreshRequested++
	if e.refreshRunning {
		e.mu.Unlock()
		return
	}
	e.refreshRunning = true
	ctx := e.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	e.mu.Unlock()
	go e.appliedRefreshLoop(ctx)
}

func (e *BillingEnforcer) calendarLoop(ctx context.Context) {
	for {
		now := e.now()
		changed := false
		subscriptionChanged, err := e.store.advanceSubscriptions(now)
		if err != nil {
			e.logger.Error("advance Proxy Node subscriptions", "error", err)
		} else {
			changed = subscriptionChanged
		}
		trafficResetAt := billingDate(now).Add(10 * time.Minute)
		if !now.Before(trafficResetAt) {
			trafficChanged, trafficErr := e.store.advanceTrafficPeriods(now)
			if trafficErr != nil {
				e.logger.Error("reset Proxy Node traffic periods", "error", trafficErr)
			} else {
				changed = changed || trafficChanged
			}
		}
		if changed {
			e.TriggerDeployment()
		}
		next := trafficResetAt
		if !now.Before(trafficResetAt) {
			next = billingDate(now).AddDate(0, 0, 1)
		}
		// Minute/hour subscriptions need enforcement before the next daily
		// quota-reset pass. A minute cadence bounds expiration delay without
		// introducing one timer per Membership.
		nextSubscriptionCheck := now.Truncate(time.Minute).Add(time.Minute)
		if nextSubscriptionCheck.Before(next) {
			next = nextSubscriptionCheck
		}
		timer := time.NewTimer(max(next.Sub(now), time.Second))
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		}
	}
}

func (e *BillingEnforcer) deploymentLoop(ctx context.Context) {
	for {
		e.mu.Lock()
		target := e.requested
		e.mu.Unlock()

		job, err := e.deployer.StartUserSync()
		joinedExisting := errors.Is(err, ErrDeploymentActive)
		if err == nil || errors.Is(err, ErrDeploymentActive) {
			for job.Status == FleetDeploymentQueued || job.Status == FleetDeploymentDeploying {
				if !waitBillingRetry(ctx, 500*time.Millisecond) {
					e.finishDeploymentLoop()
					return
				}
				job, _ = e.deployer.CurrentUserSync()
			}
			if job.Status == FleetDeploymentApplied && !joinedExisting {
				e.mu.Lock()
				if e.requested == target {
					e.running = false
					e.mu.Unlock()
					return
				}
				e.mu.Unlock()
				continue
			}
			// An unrelated deployment may have compiled an older revision just
			// before quota enforcement changed the store. As soon as it ends,
			// start again from the current revision instead of leaving the user
			// active for the normal offline-agent retry interval.
			if joinedExisting {
				continue
			}
			e.mu.Lock()
			newerRequest := e.requested != target
			e.mu.Unlock()
			if newerRequest {
				continue
			}
		}
		if err != nil && !errors.Is(err, ErrDeploymentActive) {
			e.logger.Warn("quota enforcement deployment deferred", "error", err)
		}
		if !waitBillingRetry(ctx, billingDeploymentRetry) {
			e.finishDeploymentLoop()
			return
		}
	}
}

func (e *BillingEnforcer) finishDeploymentLoop() {
	e.mu.Lock()
	e.running = false
	e.mu.Unlock()
}

func (e *BillingEnforcer) appliedRefreshLoop(ctx context.Context) {
	for {
		e.mu.Lock()
		target := e.refreshRequested
		e.mu.Unlock()
		job, err := e.deployer.StartAppliedRefresh()
		joinedExisting := errors.Is(err, ErrDeploymentActive)
		if err == nil || joinedExisting {
			for job.Status == FleetDeploymentQueued || job.Status == FleetDeploymentDeploying {
				if !waitBillingRetry(ctx, 500*time.Millisecond) {
					e.finishAppliedRefreshLoop()
					return
				}
				job, _ = e.deployer.Current()
			}
			if job.Status == FleetDeploymentApplied && !joinedExisting {
				e.mu.Lock()
				if e.refreshRequested == target {
					e.refreshRunning = false
					e.mu.Unlock()
					return
				}
				e.mu.Unlock()
				continue
			}
			if joinedExisting {
				continue
			}
		}
		if err != nil && !joinedExisting {
			e.logger.Warn("applied Proxy Node topology refresh deferred", "error", err)
		}
		if !waitBillingRetry(ctx, billingDeploymentRetry) {
			e.finishAppliedRefreshLoop()
			return
		}
	}
}

func (e *BillingEnforcer) finishAppliedRefreshLoop() {
	e.mu.Lock()
	e.refreshRunning = false
	e.mu.Unlock()
}

func waitBillingRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

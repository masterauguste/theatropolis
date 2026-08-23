package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/pool"
)

// This file wires the fleet-wide outbound pool into the control plane.
//
// Deployment records store the logical configuration (which may contain
// theatropolis-pool-ref outbounds); agents only ever receive the rendered
// document. Whenever pool content changes — a source agent applies a config
// with different inbounds, reported addresses change, an agent is revoked,
// or a manual entry is mutated — every other agent whose latest logical
// config carries refs is re-rendered and, if the rendered bytes changed,
// redeployed. Offline dependents are skipped and catch up when the
// authoritative profile is replayed on their next control connection.
//
// Concurrency: triggers fire synchronously from Connect stream handlers and
// master-local callers, but never while holding authorizationMu — the
// propagation path reaches QueueDeployment, which acquires it. The registry,
// session registry, and deployment store each have their own locking, and
// Sessions.Send only writes to a buffered channel, so the whole pass stays
// quick. All failures are logged and skipped (best-effort): connection-time
// profile synchronization re-drives anything missed.
//
// Loop safety: derivation and rendering read only the latest stored logical
// configs, and a propagation deploy never changes the dependent's own
// logical config (hence its own derived inbounds), so a propagation deploy
// cannot change what other agents render from it. The rendered-SHA dedupe
// in propagateToAgent stops any residual churn.

// deriveSource adapts the deployment store to pool.DeriveSource: the latest
// record per agent, or nil when the agent has none or the read fails.
func (s *Server) deriveSource() pool.DeriveSource {
	return func(agentID string) *deployment.Record {
		record, err := s.Deployments.LatestForAgent(context.Background(), agentID)
		if err != nil {
			return nil
		}
		return &record
	}
}

// renderLogicalConfig resolves pool refs in a logical configuration and
// returns the rendered document with its digest. With no registry (unit
// tests) the input passes through unchanged, which is correct because such
// configurations can carry no resolvable refs.
func (s *Server) renderLogicalConfig(logical []byte) ([]byte, [sha256.Size]byte, error) {
	if s.poolRegistry == nil {
		return logical, sha256.Sum256(logical), nil
	}
	rendered, _, err := pool.Render(s.poolRegistry, logical, s.deriveSource())
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return rendered, sha256.Sum256(rendered), nil
}

// poolDependents returns every agent (except exceptAgentID) whose latest
// logical configuration contains at least one pool ref, mapped to its refs.
func (s *Server) poolDependents(exceptAgentID string) map[string][]string {
	records, err := s.Deployments.List(context.Background())
	if err != nil {
		s.Logger.Error("outbound pool dependent scan failed", "error", err)
		return nil
	}
	dependents := make(map[string][]string)
	for _, record := range records {
		if record.AgentID == exceptAgentID {
			continue
		}
		if refs := pool.Refs(record.ConfigJSON); len(refs) > 0 {
			dependents[record.AgentID] = refs
		}
	}
	return dependents
}

// propagatePoolChange re-renders every dependent of the pool except
// exceptAgentID. reason is only logged.
func (s *Server) propagatePoolChange(ctx context.Context, reason, exceptAgentID string) {
	if s.poolRegistry == nil {
		return
	}
	for agentID := range s.poolDependents(exceptAgentID) {
		s.propagateToAgent(ctx, reason, agentID)
	}
}

// propagateToAgent re-renders agentID's latest logical config against the
// current pool. When the rendered digest did not change it only refreshes
// the render stamp; otherwise it queues a fresh deployment carrying the same
// logical config. Offline agents and agents with an in-flight deployment are
// skipped — the stale pool-version check on reconnect is the backstop.
func (s *Server) propagateToAgent(ctx context.Context, reason, agentID string) {
	if !s.Sessions.IsOnline(agentID) {
		return
	}
	record, err := s.Deployments.LatestForAgent(ctx, agentID)
	if err != nil {
		if !errors.Is(err, deployment.ErrNotFound) {
			s.Logger.Error(
				"outbound pool propagation could not load the latest deployment",
				"agent_id", agentID, "reason", reason, "error", err,
			)
		}
		return
	}
	_, renderedSHA, err := s.renderLogicalConfig(record.ConfigJSON)
	if err != nil {
		s.Logger.Error(
			"outbound pool propagation could not render",
			"agent_id", agentID, "reason", reason, "error", err,
		)
		return
	}
	poolVersion := s.poolRegistry.PoolVersion()

	// No-op dedupe: the freshly rendered document matches either the last
	// render stamp or the rendered digest of the record the agent was last
	// sent (which covers agents that have no stamp yet, e.g. after a master
	// restart with a legacy record). Only the stamp needs refreshing.
	_, stampedSHA, stamped := s.poolRegistry.RenderedVersion(agentID)
	if (stamped && stampedSHA == renderedSHA) || renderedSHA == record.RenderedDigest() {
		if err := s.poolRegistry.MarkRendered(agentID, poolVersion, renderedSHA); err != nil {
			s.Logger.Error(
				"outbound pool render stamp failed",
				"agent_id", agentID, "reason", reason, "error", err,
			)
		}
		return
	}

	deploymentID, err := randomOpaqueID("dep")
	if err != nil {
		s.Logger.Error(
			"outbound pool propagation could not mint a deployment ID",
			"agent_id", agentID, "reason", reason, "error", err,
		)
		return
	}
	revisionID, err := randomOpaqueID("rev")
	if err != nil {
		s.Logger.Error(
			"outbound pool propagation could not mint a revision ID",
			"agent_id", agentID, "reason", reason, "error", err,
		)
		return
	}
	// QueueDeployment re-renders the same logical config at the boundary, so
	// the agent receives identical bytes to the ones digested above unless
	// the pool changed in between; the next trigger reconciles that.
	if _, err := s.QueueDeployment(
		ctx,
		agentID,
		deploymentID,
		revisionID,
		record.ConfigJSON,
		0,
	); err != nil {
		// ErrDeploymentInProgress and ErrAgentOffline are expected races with
		// operator-driven deploys and disconnects; anything else is logged
		// the same way because propagation is best-effort.
		s.Logger.Info(
			"outbound pool propagation deployment not queued",
			"agent_id", agentID, "reason", reason, "error", err,
		)
		return
	}
	s.Logger.Info(
		"outbound pool propagation redeployed dependent",
		"agent_id", agentID, "reason", reason, "deployment_id", deploymentID,
	)
	if err := s.poolRegistry.MarkRendered(agentID, poolVersion, renderedSHA); err != nil {
		s.Logger.Error(
			"outbound pool render stamp failed",
			"agent_id", agentID, "reason", reason, "error", err,
		)
	}
}

// syncPoolAddresses persists an agent's reported addresses into the pool
// registry and propagates to dependents when they changed. Called from the
// hello and heartbeat paths with already-sanitized addresses.
func (s *Server) syncPoolAddresses(ctx context.Context, agentID string, v4, v6 []string) {
	if s.poolRegistry == nil {
		return
	}
	changed, err := s.poolRegistry.SetReported(agentID, v4, v6)
	if err != nil {
		s.Logger.Error(
			"outbound pool address persistence failed",
			"agent_id", agentID, "error", err,
		)
		return
	}
	if changed {
		s.propagatePoolChange(ctx, "reported addresses changed", agentID)
	}
}

// randomOpaqueID mints deployment and revision IDs in the same style the
// web interface uses: prefix + "_" + base64url(18 random bytes).
func randomOpaqueID(prefix string) (string, error) {
	var random [18]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(random[:])
	clear(random[:])
	return prefix + "_" + encoded, nil
}

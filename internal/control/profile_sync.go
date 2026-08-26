package control

import (
	"context"
	"errors"
	"fmt"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

// syncProfileOnConnect makes the master authoritative on every authenticated
// connection. A retained deployment is replayed to replacement hardware; an
// Agent with no deployment receives a no-listener profile, which prevents a
// configuration inherited from another master from remaining active.
func (s *Server) syncProfileOnConnect(ctx context.Context, agentID string) error {
	if !s.CanDeployProxyNodeConfiguration(agentID) {
		// An Agent without a configuration manager cannot have a managed
		// profile running, and cannot apply either a restore or a wipe.
		return nil
	}
	config := singbox.DisabledManagedConfig()
	appliedRevision := ""
	previous, err := s.Deployments.LatestForAgent(ctx, agentID)
	if err == nil {
		if applied, _, exists := previous.AppliedConfiguration(); exists {
			config = applied
			appliedRevision = previous.AppliedRevisionID()
		}
		if awaitingDeploymentReport(previous.Status) {
			if _, transitionErr := s.Deployments.Transition(
				ctx,
				previous.ID,
				deployment.StatusDeliveryFailed,
				"superseded by profile synchronization on a new control session",
				s.now(),
			); transitionErr != nil && !errors.Is(transitionErr, deployment.ErrInvalidTransition) {
				return fmt.Errorf("supersede previous deployment: %w", transitionErr)
			}
		}
	} else if !errors.Is(err, deployment.ErrNotFound) {
		return fmt.Errorf("load authoritative Agent profile: %w", err)
	}

	deploymentID, err := randomOpaqueID("dep")
	if err != nil {
		return fmt.Errorf("create profile synchronization ID: %w", err)
	}
	revisionID, err := randomOpaqueID("rev")
	if err != nil {
		return fmt.Errorf("create profile synchronization revision: %w", err)
	}
	if deployment.ClassifyRevision(appliedRevision) == deployment.RevisionPlaneProxyNodeUsers &&
		s.Sessions.Supports(agentID, ManagedUserAuthorityCapability) {
		// A replacement Agent has no persisted user-authority sidecar yet. Replay
		// an older full users-plane record as topology so the Agent first strips
		// every unproven Membership, then accepts the fresh independent authority
		// queued by the reconnect hook. This prevents a stale retained record from
		// briefly resurrecting a revoked user on replacement hardware.
		revisionID = deployment.ProxyNodeTopologyRevisionPrefix + revisionID
	} else {
		revisionID = deployment.RevisionWithSamePlane(appliedRevision, revisionID)
	}
	record, err := s.QueueDeployment(
		ctx,
		agentID,
		deploymentID,
		revisionID,
		config,
		0,
	)
	if err != nil {
		return fmt.Errorf("queue authoritative Agent profile: %w", err)
	}
	s.Logger.Info(
		"authoritative Agent profile queued on connect",
		"agent_id", agentID,
		"deployment_id", record.ID,
		"restored_previous_profile", previous.ID != "",
	)
	return nil
}

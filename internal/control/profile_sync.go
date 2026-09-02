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
	session, exists := s.Sessions.Current(agentID)
	if !exists {
		return ErrAgentOffline
	}
	return s.syncProfileOnSession(ctx, agentID, session)
}

func (s *Server) syncProfileOnSession(ctx context.Context, agentID string, session *session) error {
	return s.queueAuthoritativeProfileForSession(ctx, agentID, "Agent connected", session)
}

// queueAuthoritativeProfile replays the master's retained applied profile. It
// is used both on connection establishment and when an Agent reports that its
// active topology cannot accept the newest independent user authority.
func (s *Server) queueAuthoritativeProfile(ctx context.Context, agentID, reason string) error {
	session, exists := s.Sessions.Current(agentID)
	if !exists {
		return ErrAgentOffline
	}
	return s.queueAuthoritativeProfileForSession(ctx, agentID, reason, session)
}

func (s *Server) queueAuthoritativeProfileForSession(
	ctx context.Context,
	agentID string,
	reason string,
	session *session,
) error {
	current, exists := s.Sessions.Current(agentID)
	if !exists || current != session {
		return ErrAgentOffline
	}
	if !s.Sessions.SupportsSession(session, ProxyNodeDeployCapability, false) {
		// An Agent without a configuration manager cannot have a managed
		// profile running, and cannot apply either a restore or a wipe.
		return nil
	}
	config := singbox.DisabledManagedConfig()
	appliedRevision := ""
	rebuiltAppliedProfile := false
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
	if s.authoritativeProfileProvider != nil {
		rebuilt, managed, rebuildErr := s.authoritativeProfileProvider(ctx, agentID)
		if rebuildErr != nil {
			return fmt.Errorf("rebuild authoritative Agent profile: %w", rebuildErr)
		}
		if managed {
			config = rebuilt
			rebuiltAppliedProfile = true
		}
	}

	deploymentID, err := randomOpaqueID("dep")
	if err != nil {
		return fmt.Errorf("create profile synchronization ID: %w", err)
	}
	revisionID, err := randomOpaqueID("rev")
	if err != nil {
		return fmt.Errorf("create profile synchronization revision: %w", err)
	}
	if s.Sessions.SupportsSession(session, ManagedUserAuthorityCapability, false) {
		// Every authoritative replay to an authority-capable Agent is classified as
		// topology. The Agent can then overlay its persisted authority or strip every
		// unproven Membership before activation. This covers replacement hardware,
		// legacy generic/users-plane records, and topology-mismatch repair without
		// briefly resurrecting a stale or revoked credential.
		revisionID = deployment.ProxyNodeTopologyRevisionPrefix + revisionID
	} else {
		revisionID = deployment.RevisionWithSamePlane(appliedRevision, revisionID)
	}
	record, err := s.queueDeployment(
		ctx,
		agentID,
		deploymentID,
		revisionID,
		config,
		0,
		true,
		session,
	)
	if err != nil {
		return fmt.Errorf("queue authoritative Agent profile: %w", err)
	}
	// Only now may topology/user reconcilers treat this new session as
	// deployable. The profile record already occupies the Agent's deployment
	// slot, so a concurrent desired-topology retry observes it as busy instead
	// of racing ahead of the authoritative applied replay.
	if !s.Sessions.MarkProfileReady(session) {
		return ErrAgentOffline
	}
	s.Logger.Info(
		"authoritative Agent profile queued",
		"agent_id", agentID,
		"deployment_id", record.ID,
		"restored_previous_profile", previous.ID != "",
		"rebuilt_applied_profile", rebuiltAppliedProfile,
		"reason", reason,
	)
	return nil
}

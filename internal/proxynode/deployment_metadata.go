package proxynode

// FleetDeploymentKind identifies which configuration plane produced the
// current fleet job. It is intentionally read-only presentation metadata: the
// deployment itself remains controlled exclusively by Deployer.
type FleetDeploymentKind string

const (
	FleetDeploymentKindTopology       FleetDeploymentKind = "topology"
	FleetDeploymentKindAppliedRefresh FleetDeploymentKind = "applied_refresh"
	FleetDeploymentKindRecovery       FleetDeploymentKind = "recovery"
)

// FleetDeploymentMetadata lets read-only consumers distinguish a job for the
// current desired topology from an unrelated applied-topology refresh. The
// job ID argument keeps the metadata tied to the same Current snapshot even
// when a reconciler replaces the job concurrently.
type FleetDeploymentMetadata struct {
	Kind                FleetDeploymentKind
	TopologyRevision    uint64
	RecoveryStillNeeded bool
}

func (d *Deployer) DeploymentMetadata(jobID string) (FleetDeploymentMetadata, bool) {
	if d == nil || jobID == "" {
		return FleetDeploymentMetadata{}, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.job == nil || d.job.ID != jobID {
		return FleetDeploymentMetadata{}, false
	}
	metadata := FleetDeploymentMetadata{
		TopologyRevision:    d.job.topologyRevision,
		RecoveryStillNeeded: d.transaction != nil,
	}
	switch d.job.plane {
	case deploymentAppliedRefresh:
		metadata.Kind = FleetDeploymentKindAppliedRefresh
	case deploymentRecovery:
		metadata.Kind = FleetDeploymentKindRecovery
	default:
		metadata.Kind = FleetDeploymentKindTopology
	}
	return metadata, true
}

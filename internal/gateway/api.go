package gateway

import "net/http"

// buildHandler wires all REST and SSE routes onto a new ServeMux.
// Uses Go 1.22+ method-prefixed patterns ("GET /path", "POST /path").
func buildHandler(gw *Gateway) http.Handler {
	mux := http.NewServeMux()

	// Root/help
	mux.HandleFunc("GET /", gw.handleRoot)
	mux.HandleFunc("GET /ui", gw.handleUIIndex)
	mux.HandleFunc("GET /ui/", gw.handleUIIndex)
	mux.HandleFunc("GET /ui/app.css", gw.handleUIAsset)
	mux.HandleFunc("GET /ui/app.js", gw.handleUIAsset)
	mux.HandleFunc("GET /ui/js/", gw.handleUIAsset)

	// Health / status
	mux.HandleFunc("GET /health", gw.handleHealth)
	mux.HandleFunc("GET /api/status", gw.handleStatus)

	// Scan jobs
	mux.HandleFunc("GET /api/jobs", gw.handleListJobs)
	mux.HandleFunc("GET /api/jobs/repos", gw.handleListJobRepos)
	mux.HandleFunc("GET /api/jobs/lookup", gw.handleLookupJob)
	mux.HandleFunc("DELETE /api/jobs", gw.handleDeleteJobs)
	mux.HandleFunc("GET /api/jobs/summary", gw.handleJobsSummary)
	mux.HandleFunc("GET /api/jobs/{id}", gw.handleGetJob)
	mux.HandleFunc("GET /api/jobs/{id}/history", gw.handleGetJobHistory)
	mux.HandleFunc("DELETE /api/jobs/{id}", gw.handleDeleteJob)
	mux.HandleFunc("GET /api/jobs/{id}/scanners", gw.handleListJobScanners)
	mux.HandleFunc("GET /api/jobs/{id}/findings", gw.handleListJobFindings)
	mux.HandleFunc("GET /api/jobs/{id}/fixes", gw.handleListJobFixes)
	mux.HandleFunc("GET /api/jobs/{id}/remediation", gw.handleListJobRemediationRuns)
	mux.HandleFunc("GET /api/jobs/{id}/raw/{scanner}", gw.handleGetJobRawScannerOutput)
	mux.HandleFunc("POST /api/jobs/{id}/remediation/stop", gw.handleStopJobRemediation)
	mux.HandleFunc("POST /api/scan", gw.handleTriggerScan)

	// Agent runtime controls
	mux.HandleFunc("GET /api/agent/health", gw.handleAgentHealth)
	mux.HandleFunc("GET /api/agent", gw.handleAgentStatus)
	mux.HandleFunc("POST /api/agent/preview", gw.handleAgentPreview)
	mux.HandleFunc("POST /api/agent/trigger", gw.handleAgentTrigger)
	mux.HandleFunc("POST /api/agent/stop", gw.handleAgentStop)
	mux.HandleFunc("POST /api/agent/pause", gw.handleAgentPause)
	mux.HandleFunc("POST /api/agent/resume", gw.handleAgentResume)
	mux.HandleFunc("PUT /api/agent/workers", gw.handleAgentWorkers)
	mux.HandleFunc("GET /api/agent/workers", gw.handleAgentWorkersList)

	// Findings (read-only aggregated view)
	mux.HandleFunc("GET /api/findings", gw.handleListFindings)
	mux.HandleFunc("GET /api/findings/path-ignores", gw.handleListFindingPathIgnores)
	mux.HandleFunc("POST /api/findings/path-ignores", gw.handleCreateFindingPathIgnore)
	mux.HandleFunc("PUT /api/findings/path-ignores/{id}", gw.handleUpdateFindingPathIgnore)
	mux.HandleFunc("DELETE /api/findings/path-ignores/{id}", gw.handleDeleteFindingPathIgnore)
	mux.HandleFunc("GET /api/logs", gw.handleLogs)

	// Vulnerabilities — cross-job unified finding list with fix linkage
	mux.HandleFunc("GET /api/vulnerabilities", gw.handleListVulnerabilities)

	// Fix queue + approval
	mux.HandleFunc("GET /api/fix-queue", gw.handleListFixQueue)
	mux.HandleFunc("POST /api/fix-queue/{id}/approve", gw.handleFixApprove)
	mux.HandleFunc("POST /api/fix-queue/{id}/approve-and-run", gw.handleFixApproveAndRun)
	mux.HandleFunc("POST /api/fix-queue/{id}/reject", gw.handleFixReject)

	// Schedule management
	mux.HandleFunc("GET /api/schedules", gw.handleListSchedules)
	mux.HandleFunc("POST /api/schedules", gw.handleCreateSchedule)
	mux.HandleFunc("PUT /api/schedules/{id}", gw.handleUpdateSchedule)
	mux.HandleFunc("DELETE /api/schedules/{id}", gw.handleDeleteSchedule)
	mux.HandleFunc("POST /api/schedules/{id}/trigger", gw.handleTriggerSchedule)

	// Remediation campaigns (offline AI fix/PR workflow on existing findings)
	mux.HandleFunc("GET /api/remediation/campaigns", gw.handleListRemediationCampaigns)
	mux.HandleFunc("POST /api/remediation/campaigns", gw.handleCreateRemediationCampaign)
	mux.HandleFunc("GET /api/remediation/campaigns/{id}", gw.handleGetRemediationCampaign)
	mux.HandleFunc("GET /api/remediation/campaigns/{id}/tasks", gw.handleListRemediationCampaignTasks)
	mux.HandleFunc("POST /api/remediation/campaigns/{id}/start", gw.handleStartRemediationCampaign)
	mux.HandleFunc("POST /api/remediation/campaigns/{id}/stop", gw.handleStopRemediationCampaign)

	// Server-Sent Events stream
	mux.HandleFunc("GET /events", gw.handleEvents)

	// Config management
	mux.HandleFunc("GET /api/config", gw.handleGetConfig)
	mux.HandleFunc("PUT /api/config", gw.handlePutConfig)

	// Notification test
	mux.HandleFunc("POST /api/notify/test", gw.handleNotifyTest)

	// OSV advisory feed state
	mux.HandleFunc("GET /api/advisory/state", gw.handleAdvisoryState)

	// Scan profiles
	mux.HandleFunc("GET /api/profiles", gw.handleListProfiles)
	mux.HandleFunc("GET /api/profiles/{name}", gw.handleGetProfile)
	mux.HandleFunc("POST /api/profiles", gw.handleCreateProfile)
	mux.HandleFunc("DELETE /api/profiles/{name}", gw.handleDeleteProfile)

	return mux
}

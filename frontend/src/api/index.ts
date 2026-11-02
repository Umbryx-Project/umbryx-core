/**
 * Unified API client.
 *
 * All functions return Promise<unknown> — response shapes are not yet typed.
 * Add specific return types here as TypeScript migration progresses (B7-7).
 */
import { req, upload, uploadForm, download } from './client.js';

type ParamValue = string | number | null;

export const api = {
  // Auth
  authStatus:  ()         => req('GET',  '/auth/status',  undefined, false),
  authSetup:   (data: unknown)     => req('POST', '/auth/setup',   data, false),
  authLogin:   (data: unknown)     => req('POST', '/auth/login',   data, false),
  authMe:      ()         => req('GET',  '/auth/me'),
  authUpdateMe:(data: unknown)     => req('PATCH','/auth/me',      data),
  authChangePassword: (data: unknown) => req('POST', '/auth/change-password', data),
  authLogout:  ()         => req('POST', '/auth/logout', undefined, false),
  authMfaVerify:  (data: unknown) => req('POST', '/auth/mfa/verify',  data, false),
  authMfaSetup:   ()              => req('POST', '/auth/mfa/setup'),
  authMfaEnable:  (data: unknown) => req('POST', '/auth/mfa/enable',  data),
  authMfaDisable: (data: unknown) => req('POST', '/auth/mfa/disable', data),

  // Admin
  adminListUsers:   ()          => req('GET',    '/admin/users'),
  adminCreateUser:  (data: unknown)      => req('POST',   '/admin/users',       data),
  adminUpdateUser:  (id: string, data: unknown)  => req('PATCH',  `/admin/users/${id}`, data),
  adminDeleteUser:  (id: string)        => req('DELETE', `/admin/users/${id}`),
  // Audit integrity (B9-4)
  adminAuditStatus:  ()              => req('GET', '/admin/audit/status'),
  adminAuditVerify:  (pid?: string)  => req('GET', `/admin/audit/verify${pid ? '?pid=' + encodeURIComponent(pid) : ''}`),

  adminListModules:   ()          => req('GET',    '/admin/modules'),
  adminCreateModule:  (data: unknown)      => req('POST',   '/admin/modules',       data),
  adminUpdateModule:  (name: string, data: unknown)=> req('PATCH',  `/admin/modules/${encodeURIComponent(name)}`, data),
  adminDeleteModule:  (name: string)      => req('DELETE', `/admin/modules/${encodeURIComponent(name)}`),
  adminDownloadModuleTemplate: () => download('/admin/modules/template'),
  adminDownloadFrontendModuleTemplate: () => download('/admin/modules/template/frontend'),
  adminValidateModule: (data: unknown)     => req('POST',   '/admin/modules/validate', data),
  adminSignModule:     (data: unknown)     => req('POST',   '/admin/modules/sign',     data),
  adminUploadModule:    (file: File)    => upload('/admin/modules/upload', file),
  adminGetAttackerSSHConfig: ()   => req('GET', '/admin/modules/attacker-ssh/config'),
  adminCreateAttackerTarget: (data: unknown) => req('POST', '/admin/modules/attacker-ssh/targets', data),
  adminUpdateAttackerTarget: (id: string, data: unknown) => req('PATCH', `/admin/modules/attacker-ssh/targets/${encodeURIComponent(id)}`, data),
  adminDeleteAttackerTarget: (id: string) => req('DELETE', `/admin/modules/attacker-ssh/targets/${encodeURIComponent(id)}`),
  adminTestAttackerTarget: (id: string)   => req('POST', `/admin/modules/attacker-ssh/targets/${encodeURIComponent(id)}/test`),
  adminTestAttackerSSH: (data: unknown)    => req('POST', '/admin/modules/attacker-ssh/test', data),
  adminExecuteAttackerSSH: (data: unknown) => req('POST', '/admin/modules/attacker-ssh/execute', data),

  // Projects
  getProjects:   ()         => req('GET',    '/projects'),
  createProject: (data: unknown)     => req('POST',   '/projects',        data),
  updateProject: (id: string, data: unknown) => req('PATCH',  `/projects/${id}`,  data),
  getIntensityProfiles: () => req('GET', '/projects/meta/intensity-profiles'),
  deleteProject: (id: string)       => req('DELETE', `/projects/${id}`),

  // Notes
  getNotes:             (pid?: string)       => req('GET',    `/notes${pid ? '?pid=' + pid : ''}`),
  createNote:           (data: unknown)      => req('POST',   '/notes',               data),
  updateNote:           (id: string, data: unknown)  => req('PATCH',  `/notes/${id}`,         data),
  deleteNote:           (id: string)         => req('DELETE', `/notes/${id}`),
  getNoteAttachments:   (id: string)         => req('GET',    `/notes/${id}/attachments`),
  uploadNoteAttachment: (id: string, file: File)  => upload(`/notes/${id}/attachments`, file),
  deleteAttachment:     (id: string)         => req('DELETE', `/attachments/${id}`),

  // Hosts
  getHosts:    (pid?: string)        => req('GET',    `/hosts${pid ? '?pid=' + pid : ''}`),
  createHost:  (data: unknown)       => req('POST',   '/hosts',          data),
  updateHost:  (id: string, data: unknown)   => req('PATCH',  `/hosts/${id}`,    data),
  deleteHost:  (id: string)          => req('DELETE', `/hosts/${id}`),
  getHostTransport:        (hid: string)                     => req('GET',    `/hosts/${hid}/transport`),
  burnHost:                (hid: string)                     => req('POST',   `/hosts/${hid}/burn`),
  getBurnChecklist:        (hid: string)                     => req('GET',    `/hosts/${hid}/burn-checklist`),

  // Creds
  getCreds:    (pid?: string)        => req('GET',    `/creds${pid ? '?pid=' + pid : ''}`),
  createCred:  (data: unknown)       => req('POST',   '/creds',          data),
  updateCred:  (id: string, data: unknown)   => req('PATCH',  `/creds/${id}`,    data),
  deleteCred:  (id: string)          => req('DELETE', `/creds/${id}`),
  revealCredSecret: (id: string)     => req('GET',    `/creds/${id}/secret`),

  // Networks
  getNetworks:    (pid?: string)       => req('GET',    `/networks${pid ? '?pid=' + pid : ''}`),
  getNetworkSummary: (id: string)      => req('GET',    `/networks/${id}/summary`),
  getNetworkViewport: (id: string, x1: number, y1: number, x2: number, y2: number) => req('GET', `/networks/${id}/viewport?x1=${x1}&y1=${y1}&x2=${x2}&y2=${y2}`),
  createNetwork:  (data: unknown)      => req('POST',   '/networks',        data),
  updateNetwork:  (id: string, data: unknown)  => req('PATCH',  `/networks/${id}`,  data),
  deleteNetwork:  (id: string)         => req('DELETE', `/networks/${id}`),
  createNetworkNode:         (pid: string, data: unknown) => req('POST',   `/projects/${pid}/network/nodes`, data),
  updateNetworkNode:         (pid: string, nodeId: string, networkId: string, data: unknown) => req('PATCH',  `/projects/${pid}/network/nodes/${nodeId}?network_id=${encodeURIComponent(networkId)}`, data),
  updateNetworkNodePosition: (pid: string, nodeId: string, networkId: string, data: unknown) => req('PATCH',  `/projects/${pid}/network/nodes/${nodeId}/position?network_id=${encodeURIComponent(networkId)}`, data),
  deleteNetworkNode:         (pid: string, nodeId: string, networkId: string) => req('DELETE', `/projects/${pid}/network/nodes/${nodeId}?network_id=${encodeURIComponent(networkId)}`),
  createNetworkLink:         (pid: string, data: unknown) => req('POST',   `/projects/${pid}/network/links`, data),
  updateNetworkLink:         (pid: string, linkId: string, networkId: string, data: unknown) => req('PATCH',  `/projects/${pid}/network/links/${linkId}?network_id=${encodeURIComponent(networkId)}`, data),
  deleteNetworkLink:         (pid: string, linkId: string, networkId: string) => req('DELETE', `/projects/${pid}/network/links/${linkId}?network_id=${encodeURIComponent(networkId)}`),
  createNetworkRegion:       (pid: string, data: unknown) => req('POST',   `/projects/${pid}/network/regions`, data),
  updateNetworkRegion:       (pid: string, regionId: string, networkId: string, data: unknown) => req('PATCH',  `/projects/${pid}/network/regions/${regionId}?network_id=${encodeURIComponent(networkId)}`, data),
  deleteNetworkRegion:       (pid: string, regionId: string, networkId: string) => req('DELETE', `/projects/${pid}/network/regions/${regionId}?network_id=${encodeURIComponent(networkId)}`),

  // Findings
  getFindings:    (pid?: string, params: Record<string, ParamValue> = {}) => {
    const qs = new URLSearchParams({ ...(pid ? { pid } : {}), ...Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][]) }).toString();
    return req('GET', `/findings${qs ? '?' + qs : ''}`);
  },
  createFinding:  (data: unknown)      => req('POST',   '/findings',          data),
  updateFinding:  (id: string, data: unknown)  => req('PATCH',  `/findings/${id}`,    data),
  deleteFinding:  (id: string)         => req('DELETE', `/findings/${id}`),
  scanCandidates: (pid: string)        => req('POST',   `/findings/scan-candidates?pid=${pid}`),

  // Checklist
  getChecklist:        (pid: string, phase?: string) => req('GET',    `/checklist?pid=${pid}${phase ? '&phase=' + phase : ''}`),
  bulkCreateChecklist: (items: unknown)     => req('POST',   '/checklist',         items),
  updateChecklistItem: (id: string, data: unknown)  => req('PATCH',  `/checklist/${id}`,   data),
  deleteChecklistItem: (id: string)         => req('DELETE', `/checklist/${id}`),

  // Timeline
  getTimeline:       (pid: string, entity?: string) => req('GET', `/timeline?pid=${pid}${entity ? '&entity=' + entity : ''}`),
  undoTimelineEvent: (eventId: string) => req('POST', `/timeline/${eventId}/undo`),
  listSnapshots:     (pid: string) => req('GET',    `/projects/${pid}/snapshots`),
  createSnapshot:    (pid: string, data: unknown) => req('POST',   `/projects/${pid}/snapshots`, data),
  deleteSnapshot:    (pid: string, sid: string) => req('DELETE', `/projects/${pid}/snapshots/${sid}`),
  applySnapshot:     (pid: string, sid: string, data: unknown) => req('POST', `/projects/${pid}/snapshots/${sid}/apply`, data),

  // Objectives
  getObjectives:    (pid?: string)       => req('GET',    `/objectives${pid ? '?pid=' + pid : ''}`),
  createObjective:  (data: unknown)      => req('POST',   '/objectives',           data),
  updateObjective:  (id: string, data: unknown)  => req('PATCH',  `/objectives/${id}`,     data),
  deleteObjective:  (id: string)         => req('DELETE', `/objectives/${id}`),

  // Attack Paths
  getAttackPaths:   (pid?: string)       => req('GET',    `/attack-paths${pid ? '?pid=' + pid : ''}`),
  createAttackPath: (data: unknown)      => req('POST',   '/attack-paths',           data),
  updateAttackPath: (id: string, data: unknown)  => req('PATCH',  `/attack-paths/${id}`,     data),
  deleteAttackPath: (id: string)         => req('DELETE', `/attack-paths/${id}`),

  // Attack Steps
  getAttackSteps:   (pid?: string)       => req('GET',    `/attack-steps${pid ? '?pid=' + pid : ''}`),
  createAttackStep: (data: unknown)      => req('POST',   '/attack-steps',           data),
  updateAttackStep: (id: string, data: unknown)  => req('PATCH',  `/attack-steps/${id}`,     data),
  deleteAttackStep: (id: string)         => req('DELETE', `/attack-steps/${id}`),
  moveStep:         (id: string, data: { parent_step_id?: string | null, step_order?: number }) => req('POST', `/attack-steps/${id}/move`, data),

  // Attack Path Nodes (v2 graph)
  listAttackPathNodes:      (pathId: string)        => req('GET',  `/attack-path-nodes?path_id=${encodeURIComponent(pathId)}`),
  createAttackPathNode:     (data: unknown)         => req('POST', '/attack-path-nodes', data),
  updateAttackPathNode:     (id: string, data: unknown) => req('PATCH', `/attack-path-nodes/${id}`, data),
  deleteAttackPathNode:     (id: string)            => req('DELETE', `/attack-path-nodes/${id}`),

  // Attack Path Edges (v2 graph)
  listAttackPathEdges:      (pathId: string)        => req('GET',  `/attack-path-edges?path_id=${encodeURIComponent(pathId)}`),
  createAttackPathEdge:     (data: unknown)         => req('POST', '/attack-path-edges', data),
  updateAttackPathEdge:     (id: string, data: unknown) => req('PATCH', `/attack-path-edges/${id}`, data),
  deleteAttackPathEdge:     (id: string)            => req('DELETE', `/attack-path-edges/${id}`),

  // Attack Path Branches (v2 graph)
  listAttackPathBranches:   (pathId: string)        => req('GET',  `/attack-path-branches?path_id=${encodeURIComponent(pathId)}`),
  createAttackPathBranch:   (data: unknown)         => req('POST', '/attack-path-branches', data),
  updateAttackPathBranch:   (id: string, data: unknown) => req('PATCH', `/attack-path-branches/${id}`, data),
  deleteAttackPathBranch:   (id: string)            => req('DELETE', `/attack-path-branches/${id}`),

  // Entity Links
  listEntityLinks:          (pid: string, params?: Record<string, string>) => {
    const qs = new URLSearchParams({ pid, ...Object.fromEntries(Object.entries(params || {}).filter(([, v]) => v)) }).toString();
    return req('GET', `/entity-links?${qs}`);
  },
  createEntityLink:         (data: unknown)         => req('POST', '/entity-links', data),
  deleteEntityLink:         (id: string)            => req('DELETE', `/entity-links/${id}`),

  // Loot
  getLoots:    (pid?: string, params: Record<string, ParamValue> = {}) => {
    const qs = new URLSearchParams({ ...(pid ? { pid } : {}), ...Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][]) }).toString();
    return req('GET', `/loots${qs ? '?' + qs : ''}`);
  },
  createLoot:  (data: unknown)      => req('POST',   '/loots',          data),
  updateLoot:  (id: string, data: unknown)  => req('PATCH',  `/loots/${id}`,    data),
  deleteLoot:  (id: string)         => req('DELETE', `/loots/${id}`),
  uploadLootFile: (id: string, file: File) => upload(`/loots/${id}/file`, file),
  getJobArtifacts: (pid: string, jobId: string) => req('GET', `/projects/${pid}/jobs/${jobId}/artifacts`),

  // Scope
  getScopes:    (pid?: string)      => req('GET',    `/scopes${pid ? '?pid=' + pid : ''}`),
  createScope:  (data: unknown)     => req('POST',   '/scopes',          data),
  updateScope:  (id: string, data: unknown) => req('PATCH',  `/scopes/${id}`,    data),
  deleteScope:  (id: string)        => req('DELETE', `/scopes/${id}`),

  // Surface watch (continuous attack-surface monitoring)
  getProjectWatches:   (pid: string)          => req('GET',    `/projects/${pid}/watch`),
  createProjectWatch:  (pid: string, data: unknown) => req('POST',   `/projects/${pid}/watch`,       data),
  updateProjectWatch:  (pid: string, id: string, data: unknown) => req('PATCH',  `/projects/${pid}/watch/${id}`, data),
  deleteProjectWatch:  (pid: string, id: string) => req('DELETE', `/projects/${pid}/watch/${id}`),
  runProjectWatch:     (pid: string, id: string) => req('POST',   `/projects/${pid}/watch/${id}/run`),
  getPurpleView:        (pid: string)          => req('GET',    `/projects/${pid}/purple`),
  getDeconfliction:     (pid: string)          => req('GET',    `/projects/${pid}/deconfliction`),
  claimHost:     (pid: string, hostId: string, data?: unknown) => req('POST',   `/projects/${pid}/hosts/${hostId}/claim`, data),
  releaseHost:   (pid: string, hostId: string) => req('DELETE', `/projects/${pid}/hosts/${hostId}/claim`),

  // Host activities
  getHostActivities:  (pid?: string, hostId?: string) => req('GET', '/host-activities' + (pid || hostId ? '?' + new URLSearchParams({ ...(pid ? { pid } : {}), ...(hostId ? { host_id: hostId } : {}) }).toString() : '')),
  createHostActivity: (data: unknown)        => req('POST',   '/host-activities',          data),
  updateHostActivity: (id: string, data: unknown)    => req('PATCH',  `/host-activities/${id}`,    data),
  deleteHostActivity: (id: string)           => req('DELETE', `/host-activities/${id}`),
  executeAttackerCommand: (pid: string, data: unknown) => req('POST', `/projects/${pid}/attacker-exec`, data),
  listAttackerExecutionTargets: (pid: string) => req('GET', `/projects/${pid}/attacker-exec/targets`),

  // Cred-host notes
  getCredHostNotes:   (params: Record<string, string>) => { const qs = new URLSearchParams(params).toString(); return req('GET', `/cred-host-notes${qs ? '?' + qs : ''}`); },
  upsertCredHostNote: (data: unknown)        => req('POST',   '/cred-host-notes',       data),
  updateCredHostNote: (id: string, data: unknown)    => req('PATCH',  `/cred-host-notes/${id}`, data),
  deleteCredHostNote: (id: string)           => req('DELETE', `/cred-host-notes/${id}`),

  // Search & presence
  search:      (q: string, pid?: string, limit = 40, offset = 0) => req('GET', `/search?q=${encodeURIComponent(q)}${pid ? '&pid=' + pid : ''}&limit=${limit}&offset=${offset}`),
  listSavedSearches:   ()           => req('GET',    '/saved-searches'),
  createSavedSearch:   (data: unknown)       => req('POST',   '/saved-searches', data),
  deleteSavedSearch:   (id: string)          => req('DELETE', `/saved-searches/${id}`),
  getPresence: ()        => req('GET', '/presence'),
  getWorkerStatus: ()    => req('GET', '/worker/status'),
  listModules: ()        => req('GET', '/modules'),
  listConnectors: ()     => req('GET', '/connectors'),

  // Finding templates
  listFindingTemplates:        ()       => req('GET',    '/finding-templates'),
  listCustomFindingTemplates:  ()       => req('GET',    '/finding-templates/custom'),
  createCustomFindingTemplate: (data: unknown)   => req('POST',   '/finding-templates/custom', data),
  deleteCustomFindingTemplate: (id: string)   => req('DELETE', `/finding-templates/custom/${id}`),
  exportFindingTemplates:      ()       => download('/finding-templates/export'),
  importFindingTemplates:      (file: File)   => upload('/finding-templates/import', file),

  // Snippets
  listSnippets:        ()           => req('GET',    '/snippets'),
  listCustomSnippets:  ()           => req('GET',    '/snippets/custom'),
  createCustomSnippet: (data: unknown)       => req('POST',   '/snippets/custom',     data),
  updateCustomSnippet: (id: string, data: unknown)   => req('PATCH',  `/snippets/custom/${id}`, data),
  deleteCustomSnippet: (id: string)          => req('DELETE', `/snippets/custom/${id}`),
  exportSnippets:      ()           => download('/snippets/export'),
  importSnippets:      (file: File) => upload('/snippets/import', file),
  exportKB:            (pid?: string)        => download(`/kb/export${pid ? '?pid=' + pid : ''}`),
  importKB:            (file: File, pid?: string)  => upload(`/kb/import${pid ? '?pid=' + pid : ''}`, file),
  exportPlaybooks:        ()                       => download('/playbooks/custom/export'),
  exportSinglePlaybook:   (id: string)             => download(`/playbooks/custom/${id}/export`),
  importPlaybooks:        (file: File)             => upload('/playbooks/custom/import', file),
  exportPacks:            ()                       => download('/playbooks/packs/export'),
  importPacks:            (file: File)             => upload('/playbooks/packs/import', file),
  exportProjectBundle:    (pid: string)            => download(`/projects/${pid}/playbooks/bundle`),
  importProjectBundle:    (pid: string, file: File) => upload(`/projects/${pid}/playbooks/bundle/import`, file),
  listOperationPacks:  ()           => req('GET',    '/playbooks/packs'),
  createOperationPack: (data: unknown)       => req('POST',   '/playbooks/packs', data),
  deleteOperationPack: (packId: string)      => req('DELETE', `/playbooks/packs/${packId}`),

  // BloodHound server-side import
  importBloodHound: (pid: string, file: File) => upload(`/projects/${pid}/import/bloodhound`, file),

  // MITRE ATT&CK
  getMitreCoverage:  (pid: string) => req('GET', `/projects/${pid}/mitre/coverage`),
  downloadReportPDF: async (pid: string): Promise<Blob> => {
    const res = await fetch(`/api/projects/${pid}/report/pdf`, { credentials: 'include' });
    if (!res.ok) throw new Error(`PDF generation failed: ${res.status}`);
    return res.blob();
  },
  downloadReportHTML: async (pid: string): Promise<{ blob: Blob; filename: string }> => {
    const res = await fetch(`/api/projects/${pid}/report/html`, { credentials: 'include' });
    if (!res.ok) throw new Error(`HTML export failed: ${res.status}`);
    const cd = res.headers.get('Content-Disposition') || '';
    const match = /filename="([^"]+)"/.exec(cd);
    return { blob: await res.blob(), filename: match ? match[1] : `report_${pid}.html` };
  },
  downloadReportDraft: async (pid: string): Promise<{ blob: Blob; filename: string }> => {
    const res = await fetch(`/api/projects/${pid}/report/draft`, { credentials: 'include' });
    if (!res.ok) throw new Error(`Draft generation failed: ${res.status}`);
    const cd = res.headers.get('Content-Disposition') || '';
    const match = /filename="([^"]+)"/.exec(cd);
    return { blob: await res.blob(), filename: match ? match[1] : `draft_${pid}.md` };
  },
  getReportDraft: async (pid: string): Promise<string> => {
    const res = await fetch(`/api/projects/${pid}/report/draft`, { credentials: 'include' });
    if (!res.ok) throw new Error(`Draft generation failed: ${res.status}`);
    return res.text();
  },

  // Batch import & project export/import
  batchImport:   (pid: string, data: unknown) => req('POST', `/import/${pid}`, data),
  exportProject: async (pid: string): Promise<{ blob: Blob; password: string | null }> => {
    const res = await fetch(`/api/export/${pid}`, { credentials: 'include' });
    if (!res.ok) throw new Error(await res.text());
    const blob = await res.blob();
    const password = res.headers.get('X-Zip-Password') || null;
    return { blob, password };
  },
  importProject: (file: File, password?: string) => {
    const form = new FormData();
    form.append('file', file);
    if (password) form.append('password', password);
    return uploadForm('/import_project', form);
  },

  // Topology
  topologyPreview: (pid: string, formData: FormData) => {
    return fetch(`/api/projects/${pid}/topology/preview`, {
      method: 'POST', body: formData,
      credentials: 'include',
    }).then(async res => {
      if (!res.ok) throw new Error(await res.text());
      return res.json() as Promise<unknown>;
    });
  },
  topologyApply:         (pid: string, data: unknown)    => req('POST', `/projects/${pid}/topology/apply`,          data),
  topologyRebuildLayout: (pid: string, data: unknown)    => req('POST', `/projects/${pid}/topology/rebuild-layout`, data),
  topologyAutoBuild:     (pid: string, data: unknown)    => req('POST', `/projects/${pid}/topology/auto-build`,     data),
  topologySmartBuild:    (pid: string, data: unknown)    => req('POST', `/projects/${pid}/topology/smart-build`,    data),
  topologyLateralPaths:  (pid: string, fromHostId: string, depth = 3) => req('GET', `/projects/${pid}/topology/lateral-paths?from_host_id=${fromHostId}&depth=${depth}`),
  getTopology:           (pid: string)          => req('GET',  `/projects/${pid}/topology`),
  getTopologySources:    (pid: string)          => req('GET',  `/projects/${pid}/topology/sources`),
  // Canonical graph (GRAPH_MODEL_REFACTOR Step 2/4/6)
  getCanonicalGraph:     (pid: string, inferred = false) => req('GET', `/projects/${pid}/topology/graph${inferred ? '?inferred=true' : ''}`),
  getMapSuggestions:     (pid: string, inferred = true)  => req('GET', `/projects/${pid}/topology/graph/suggestions?inferred=${inferred}`),

  // Pivot observations
  listPivots:            (pid: string)          => req('GET',  `/projects/${pid}/pivots`),
  createPivot:           (pid: string, data: unknown)    => req('POST', `/projects/${pid}/pivots`, data),
  updatePivot:           (pid: string, pivotId: string, data: unknown) => req('PATCH', `/projects/${pid}/pivots/${pivotId}`, data),
  deletePivot:           (pid: string, pivotId: string) => req('DELETE', `/projects/${pid}/pivots/${pivotId}`),
  collectPivots:         (pid: string, data: unknown)    => req('POST', `/projects/${pid}/pivots/collect`, data),

  // Project members
  getProjectMembers:       (pid: string)             => req('GET',    `/projects/${pid}/members`),
  getProjectAvailableUsers:(pid: string)             => req('GET',    `/projects/${pid}/available-users`),
  addProjectMember:        (pid: string, data: unknown)       => req('POST',   `/projects/${pid}/members`,            data),
  bulkAddProjectMembers:   (pid: string, data: unknown)       => req('POST',   `/projects/${pid}/members/bulk`,       data),
  updateProjectMember:     (pid: string, uid: string, data: unknown)  => req('PATCH',  `/projects/${pid}/members/${uid}`,     data),
  removeProjectMember:     (pid: string, uid: string)        => req('DELETE', `/projects/${pid}/members/${uid}`),
  transferOwnership:       (pid: string, data: unknown)       => req('POST',   `/projects/${pid}/transfer-ownership`, data),
  getMyProjectPermissions: (pid: string)             => req('GET',    `/projects/${pid}/permissions/me`),

  // CSV exports
  exportHostsCsv:    (pid: string) => download(`/projects/${pid}/export/hosts.csv`),
  exportFindingsCsv: (pid: string) => download(`/projects/${pid}/export/findings.csv`),
  exportCredsCsv:    (pid: string) => download(`/projects/${pid}/export/creds.csv`),

  // Project templates
  listProjectTemplates:  ()           => req('GET',  '/project-templates'),
  applyProjectTemplate:  (templateId: string) => req('POST', `/project-templates/${templateId}/apply`),

  // Bulk host import
  bulkImportHosts: (data: unknown) => req('POST', '/hosts/bulk', data),

  // Scans (nmap/nuclei/cme via attacker SSH)
  runNmapScan:    (pid: string, data: unknown) => req('POST', `/projects/${pid}/scans/nmap`,   data),
  runNucleiScan:  (pid: string, data: unknown) => req('POST', `/projects/${pid}/scans/nuclei`, data),
  runCmeScan:     (pid: string, data: unknown) => req('POST', `/projects/${pid}/scans/cme`,    data),
  runDonpapiScan: (pid: string, data: unknown) => req('POST', `/projects/${pid}/scans/donpapi`, data),

  // Webhooks (C2)
  getProjectWebhook:        (pid: string)  => req('GET',  `/projects/${pid}/webhook`),
  regenerateProjectWebhook: (pid: string)  => req('POST', `/projects/${pid}/webhook/regenerate`),

  // C2 integrations
  listC2Integrations:    ()              => req('GET',    '/c2'),
  listC2Listeners:       (iid: string)           => req('GET',    `/infra-v2/c2/${iid}/listeners`),
  createC2Listener:      (iid: string, data: unknown)    => req('POST',   `/infra-v2/c2/${iid}/listeners`, data),
  stopC2Listener:        (iid: string, name: string)     => req('DELETE', `/infra-v2/c2/${iid}/listeners/${name}`),
  generateC2Payload:     (iid: string, data: unknown)    => req('POST',   `/infra-v2/c2/${iid}/payloads`, data),
  createC2Integration:   (data: unknown)          => req('POST',   '/c2',            data),
  updateC2Integration:   (id: string, data: unknown)      => req('PATCH',  `/c2/${id}`,      data),
  deleteC2Integration:   (id: string)            => req('DELETE', `/c2/${id}`),
  testC2Integration:     (id: string)            => req('POST',   `/c2/${id}/test`),
  syncC2ToProject:       (id: string, pid: string)       => req('POST',   `/c2/${id}/sync/${pid}`),
  listC2ForProject:      (pid: string)           => req('GET',    `/c2/for-project/${pid}`),
  getC2LiveSessions:     (pid: string)           => req('GET',    `/c2/sessions/${pid}`),
  getC2SessionsHealth:   (pid: string)           => req('GET',    `/c2/sessions/${pid}/health`),
  getC2HostActions:      (pid: string, hostId: string)   => req('GET',    `/c2/host-actions/${pid}/${hostId}`),
  listC2Bofs:            (id: string, pid: string)       => req('GET',    `/c2/${id}/bofs/${pid}`),
  executeC2HostAction:   (pid: string, data: unknown)     => req('POST',   `/c2/execute/${pid}`, data),
  assessOpsec:           (pid: string, data: unknown)     => req('POST',   `/c2/assess-opsec/${pid}`, data),
  getC2AgentTasks:       (pid: string, integrationId: string, agentId: string, limit = 30) => req('GET', `/c2/agent-tasks/${pid}?integration_id=${encodeURIComponent(integrationId)}&agent_id=${encodeURIComponent(agentId)}&limit=${encodeURIComponent(limit)}`),

  // Collections
  listCollections:   (pid: string)          => req('GET',    `/projects/${pid}/collections`),
  createCollection:  (pid: string, data: unknown)    => req('POST',   `/projects/${pid}/collections`,          data),
  updateCollection:  (pid: string, id: string, data: unknown)=> req('PATCH',  `/projects/${pid}/collections/${id}`,    data),
  deleteCollection:  (pid: string, id: string)       => req('DELETE', `/projects/${pid}/collections/${id}`),
  resolveCollection: (pid: string, id: string)       => req('GET',    `/projects/${pid}/collections/${id}/resolve`),
  previewCollection: (pid: string, filters: unknown) => req('POST',   `/projects/${pid}/collections/preview`,  filters),

  // Bulk actions
  bulkExec:      (pid: string, data: unknown)           => req('POST', `/projects/${pid}/bulk-exec`,                data),
  validateCred:  (pid: string, credId: string, data: unknown)   => req('POST', `/projects/${pid}/creds/${credId}/validate`, data),
  getCredMatrix:          (pid: string)                    => req('GET',    `/projects/${pid}/cred-matrix`),
  getCredReuse:           (pid: string)                    => req('GET',    `/projects/${pid}/cred-reuse`),

  // Scan diffing
  getScanHistory: (hostId: string)             => req('GET',  `/hosts/${hostId}/scan-history`),
  getScanDiff:    (hostId: string, oldId?: string, newId?: string) => {
    const qs = new URLSearchParams();
    if (oldId) qs.set('old_id', oldId);
    if (newId) qs.set('new_id', newId);
    const q = qs.toString();
    return req('GET', `/hosts/${hostId}/scan-diff${q ? '?' + q : ''}`);
  },

  // Host risk scores
  getRiskScores:  (pid: string)                => req('GET',  `/hosts/risk-scores?pid=${pid}`),
  getHostRisk:    (hostId: string)             => req('GET',  `/hosts/${hostId}/risk-score`),

  // Jobs
  listJobs:   (pid: string, params: Record<string, ParamValue> = {}) => {
    const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][])).toString();
    return req('GET', `/projects/${pid}/jobs${qs ? '?' + qs : ''}`);
  },
  getJob:          (pid: string, jobId: string) => req('GET',    `/projects/${pid}/jobs/${jobId}`),
  streamJobOutput: (pid: string, jobId: string) => `/api/projects/${pid}/jobs/${jobId}/output-stream`,
  deleteJob:  (pid: string, jobId: string) => req('DELETE', `/projects/${pid}/jobs/${jobId}`),
  cancelJob:  (pid: string, jobId: string) => req('PATCH',  `/projects/${pid}/jobs/${jobId}/cancel`),
  rerunJob:   (pid: string, jobId: string) => req('POST',   `/projects/${pid}/jobs/${jobId}/rerun`),
  retryJob:   (pid: string, jobId: string) => req('POST', `/projects/${pid}/jobs/${jobId}/retry`),
  approveJob: (pid: string, jobId: string) => req('POST', `/projects/${pid}/jobs/${jobId}/approve`),
  rejectJob:  (pid: string, jobId: string) => req('POST', `/projects/${pid}/jobs/${jobId}/reject`),
  requestScopeExtension: (data: { pid: string; value: string; reason?: string; blocked_job_id?: string }) => req('POST', '/scopes/extension-request', data),
  getChainSuggestions: (pid: string, jobId?: string) => req('GET', `/projects/${pid}/jobs/chain-suggestions${jobId ? '?job_id=' + jobId : ''}`),

  // Playbooks
  listPlaybooks: () => req('GET', '/playbooks'),
  listPlaybookStepTemplates: () => req('GET', '/playbooks/step-templates'),
  validatePlaybook: (data: unknown) => req('POST', '/playbooks/validate', data),
  createCustomPlaybook: (data: unknown) => req('POST', '/playbooks/custom', data),
  updateCustomPlaybook: (id: string, data: unknown) => req('PATCH', `/playbooks/custom/${id}`, data),
  deleteCustomPlaybook: (id: string) => req('DELETE', `/playbooks/custom/${id}`),
  runPlaybook: (pid: string, playbookId: string, data: unknown) => req('POST', `/projects/${pid}/playbooks/${encodeURIComponent(playbookId)}/run`, data),
  batchRunPlaybook: (pid: string, playbookId: string, data: unknown) => req('POST', `/projects/${pid}/playbooks/${encodeURIComponent(playbookId)}/batch-run`, data),
  listPlaybookRuns: (pid: string, params: Record<string, ParamValue> = {}) => {
    const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][])).toString();
    return req('GET', `/projects/${pid}/playbook-runs${qs ? '?' + qs : ''}`);
  },
  getPlaybookRun: (pid: string, runId: string) => req('GET', `/projects/${pid}/playbook-runs/${runId}`),
  cancelPlaybookRun: (pid: string, runId: string) => req('POST', `/projects/${pid}/playbook-runs/${runId}/cancel`),
  rerunPlaybookRun: (pid: string, runId: string) => req('POST', `/projects/${pid}/playbook-runs/${runId}/rerun`),

  // Notifications
  getNotificationConfig:  ()      => req('GET',  '/notifications/config'),
  saveNotificationConfig: (data: unknown)  => req('PUT',  '/notifications/config', data),
  testNotification:       ()      => req('POST', '/notifications/test'),
  getTelegramChatIds:     ()      => req('GET',  '/notifications/telegram/chat-id'),
  getNotifications:       (params?: string) => req('GET', `/notifications${params ? '?' + params : ''}`),
  getUnreadCount:         ()      => req('GET',  '/notifications/unread-count'),
  markNotificationRead:   (id: string) => req('POST', `/notifications/${id}/read`),
  markAllNotificationsRead: ()    => req('POST', '/notifications/mark-all-read'),

  // Scheduled playbooks
  listSchedules:    (pid: string)           => req('GET',    `/scheduled-playbooks?pid=${encodeURIComponent(pid)}`),
  createSchedule:   (data: unknown)          => req('POST',   '/scheduled-playbooks',        data),
  updateSchedule:   (id: string, data: unknown)      => req('PATCH',  `/scheduled-playbooks/${id}`,  data),
  deleteSchedule:   (id: string)             => req('DELETE', `/scheduled-playbooks/${id}`),
  triggerSchedule:  (id: string)             => req('POST',   `/scheduled-playbooks/${id}/trigger`),


  // AI
  getAIStatus:       ()                => req('GET',  '/ai/status'),

  // AI v2 — chat persistence + providers + streaming
  getAIProviderTypes:  ()             => req('GET',  '/ai/providers/types'),
  getAIProviders:      ()             => req('GET',  '/ai/providers'),
  migrateAIProviders:   ()             => req('POST', '/ai/providers/migrate'),
  addAIProvider:       (data: unknown)         => req('POST', '/ai/providers', data),
  updateAIProvider:    (id: string, data: unknown)      => req('PUT',  `/ai/providers/${id}`, data),
  removeAIProvider:    (id: string)           => req('DELETE', `/ai/providers/${id}`),
  testAIProvider:      (id: string)           => req('POST', `/ai/providers/${id}/test`),
  getAIProviderModels: (id: string)           => req('POST', `/ai/providers/${id}/models`),
  fetchAIProviderModels: (data: unknown)       => req('POST', '/ai/providers/fetch-models', data),
  getAISettings:       ()             => req('GET',  '/ai/settings'),
  saveAISettings:      (data: unknown)         => req('PUT',  '/ai/settings', data),
  getAITools:          ()             => req('GET',  '/ai/tools'),
  getAIChats:          (pid: string)           => req('GET',  `/projects/${pid}/ai/chats`),
  createAIChat:        (pid: string, data: unknown)      => req('POST', `/projects/${pid}/ai/chats`, data),
  listAIAgents:        ()                     => req('GET',    '/ai/agents'),
  getAIChat:           (pid: string, cid: string)        => req('GET',  `/projects/${pid}/ai/chats/${cid}`),
  deleteAIChat:        (pid: string, cid: string)        => req('DELETE', `/projects/${pid}/ai/chats/${cid}`),
  sendAIMessage:       (pid: string, cid: string, data: unknown) => req('POST', `/projects/${pid}/ai/chats/${cid}/messages`, data),
  getAIAudit:          (pid: string, limit = 100)        => req('GET',  `/projects/${pid}/ai/audit?limit=${limit}`),

  // Playbook Automation v2
  listAutomations:        (pid: string)           => req('GET',    `/projects/${pid}/automations`),
  createAutomation:       (pid: string, data: unknown)    => req('POST',   `/projects/${pid}/automations`, data),
  getAutomation:          (pid: string, aid: string)      => req('GET',    `/projects/${pid}/automations/${aid}`),
  updateAutomation:       (pid: string, aid: string, data: unknown) => req('PUT', `/projects/${pid}/automations/${aid}`, data),
  deleteAutomation:       (pid: string, aid: string)      => req('DELETE', `/projects/${pid}/automations/${aid}`),
  enableAutomation:       (pid: string, aid: string)      => req('POST',   `/projects/${pid}/automations/${aid}/enable`),
  disableAutomation:      (pid: string, aid: string)      => req('POST',   `/projects/${pid}/automations/${aid}/disable`),
  validateAutomation:     (pid: string, aid: string)      => req('POST',   `/projects/${pid}/automations/${aid}/validate`),
  validateAutomationDef:  (pid: string, data: unknown)    => req('POST',   `/projects/${pid}/automations/validate-def`, data),
  runAutomation:          (pid: string, aid: string, data?: unknown) => req('POST', `/projects/${pid}/automations/${aid}/run`, data || {}),
  listAutomationRuns:     (pid: string, aid: string, params?: string) => req('GET', `/projects/${pid}/automations/${aid}/runs${params ? '?' + params : ''}`),
  getAutomationRun:       (pid: string, aid: string, rid: string) => req('GET', `/projects/${pid}/automations/${aid}/runs/${rid}`),
  cancelAutomationRun:    (pid: string, aid: string, rid: string) => req('POST', `/projects/${pid}/automations/${aid}/runs/${rid}/cancel`),
  killAllAutomations:     (pid: string)           => req('POST',   `/projects/${pid}/automations/kill-all`),
  getAutomationTemplates: (pid: string)           => req('GET',    `/projects/${pid}/automations/templates`),
  getAutomationTools:     (pid: string)           => req('GET',    `/projects/${pid}/automations/tools`),
  exportAutomation:       (pid: string, aid: string)      => req('GET',    `/projects/${pid}/automations/${aid}/export`),
  importAutomation:       (pid: string, data: unknown)    => req('POST',   `/projects/${pid}/automations/import`, data),
  dryRunAutomation:       (pid: string, aid: string, data?: unknown) => req('POST', `/projects/${pid}/automations/${aid}/dry-run`, data || {}),

  // Import scanners
  importNessus:      (pid: string, file: File)       => upload(`/projects/${pid}/import/nessus`, file),
  importBurp:        (pid: string, file: File)       => upload(`/projects/${pid}/import/burp`, file),

  // Firewall/router config import
  firewallConfigDetect: (pid: string, file: File) => {
    const f = new FormData(); f.append('file', file);
    return uploadForm(`/projects/${pid}/firewall-configs/detect`, f);
  },
  firewallConfigPreview: (pid: string, file: File) => {
    const f = new FormData(); f.append('file', file);
    return uploadForm(`/projects/${pid}/firewall-configs/preview`, f);
  },
  firewallConfigApply: (pid: string, file: File) => {
    const f = new FormData(); f.append('file', file);
    return uploadForm(`/projects/${pid}/firewall-configs/apply`, f);
  },
  listFirewallConfigs:   (pid: string)              => req('GET', `/projects/${pid}/firewall-configs`),
  getFirewallConfigDiff: (pid: string, uploadId: string) => req('GET', `/projects/${pid}/firewall-configs/${uploadId}/diff`),

  // Attack graph
  getAttackGraph:    (pid: string)             => req('GET',  `/projects/${pid}/attack-graph`),

  // Attack path versions
  getAttackPathVersions:    (pathId: string)              => req('GET',  `/attack-paths/${pathId}/versions`),
  createAttackPathSnapshot: (pathId: string)              => req('POST', `/attack-paths/${pathId}/snapshot`),
  revertAttackPathVersion:  (pathId: string, version: number) => req('POST', `/attack-paths/${pathId}/revert/${version}`),

  // Dependency graph
  getDependencyGraph: (pid: string, rootType: string, rootId: string) => req('GET', `/entity-links/dependency-graph?pid=${encodeURIComponent(pid)}&root_type=${encodeURIComponent(rootType)}&root_id=${encodeURIComponent(rootId)}`),

  // Risk recalculation
  recalculateRisk: (pathId: string) => req('POST', `/attack-paths/${pathId}/recalculate-risk`),

  // Tasks
  listTasks:    (pid: string, params: Record<string, ParamValue> = {}) => {
    const qs = new URLSearchParams({ pid, ...Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][]) }).toString();
    return req('GET', `/tasks?${qs}`);
  },
  createTask:   (data: unknown)      => req('POST',   '/tasks',          data),
  updateTask:   (id: string, data: unknown)  => req('PATCH',  `/tasks/${id}`,    data),
  deleteTask:   (id: string)         => req('DELETE', `/tasks/${id}`),

  // Remediations
  listRemediations:    (pid: string, params: Record<string, ParamValue> = {}) => {
    const qs = new URLSearchParams({ pid, ...Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][]) }).toString();
    return req('GET', `/remediations?${qs}`);
  },
  createRemediation:   (data: unknown)      => req('POST',   '/remediations',          data),
  updateRemediation:   (id: string, data: unknown)  => req('PATCH',  `/remediations/${id}`,    data),
  deleteRemediation:   (id: string)         => req('DELETE', `/remediations/${id}`),

  // Evidence
  listEvidence:    (pid: string) => req('GET', `/evidence?pid=${encodeURIComponent(pid)}`),
  createEvidence:  (data: unknown)      => req('POST',   '/evidence',          data),
  deleteEvidence:  (id: string)         => req('DELETE', `/evidence/${id}`),

  // Identities
  listIdentities:    (pid: string) => req('GET', `/identities?pid=${encodeURIComponent(pid)}`),
  createIdentity:    (data: unknown)      => req('POST',   '/identities',          data),
  updateIdentity:    (id: string, data: unknown)  => req('PATCH',  `/identities/${id}`,    data),
  deleteIdentity:    (id: string)         => req('DELETE', `/identities/${id}`),

  // Metrics
  getMetrics:    (pid: string, scope = 'local') => req('GET', `/metrics?pid=${encodeURIComponent(pid)}&scope=${encodeURIComponent(scope)}`),

  // Sync
  syncPush:             (data: unknown)       => req('POST',   '/sync/push',          data),
  syncPull:             (instanceId: string, sinceSeq: number, pid: string) => req('GET', `/sync/pull?instance_id=${encodeURIComponent(instanceId)}&since_seq=${sinceSeq}&pid=${encodeURIComponent(pid)}`),
  getSyncStatus:        (pid: string)         => req('GET',    `/sync/status?pid=${encodeURIComponent(pid)}`),
  resolveConflict:      (conflictId: string, data: unknown) => req('POST', `/sync/conflicts/${encodeURIComponent(conflictId)}/resolve`, data),
  getSyncPolicy:        (pid: string)         => req('GET',    `/sync/policy?pid=${encodeURIComponent(pid)}`),
  updateSyncPolicy:     (data: unknown)       => req('PUT',    '/sync/policy',         data),

  // Audit log
  getAuditLog: (params: string) => req('GET', `/audit/log?${params}`),

  // Knowledge base
  listKBArticles:    (params: Record<string, string | number | null> = {})       => { const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][])).toString(); return req('GET', `/kb${qs ? '?' + qs : ''}`); },
  getKBArticles:     (params: Record<string, string | number | null> = {})       => { const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][])).toString(); return req('GET', `/kb${qs ? '?' + qs : ''}`); },
  getKBArticle:      (id: string)              => req('GET',  `/kb/${id}`),
  createKBArticle:   (data: unknown)            => req('POST', '/kb', data),
  updateKBArticle:   (id: string, data: unknown)         => req('PATCH', `/kb/${id}`, data),
  deleteKBArticle:   (id: string)              => req('DELETE', `/kb/${id}`),
  seedMitreKB:       ()               => req('POST', '/kb/seed/mitre'),

  // ── Image Registries ───────────────────────────────────────────
  // orgId is optional — omit for the platform-wide list (platform_admin
  // only); pass it to read/write a single organization's own registries
  // (org owner/admin, or platform_admin).
  listImageRegistries:   (orgId?: string) => req('GET', `/workstations/image-registries${orgId ? `?org_id=${orgId}` : ''}`),
  addImageRegistry:      (data: unknown, orgId?: string)  => req('POST', `/workstations/image-registries${orgId ? `?org_id=${orgId}` : ''}`, data),
  deleteImageRegistry:   (id: string, orgId?: string)     => req('DELETE', `/workstations/image-registries/${id}${orgId ? `?org_id=${orgId}` : ''}`),

  // ── Workstations ────────────────────────────────────────────────
  listWsProviders:       ()               => req('GET', '/workstations/providers'),
  listWsInfraProviders:  (provider: string) => req('GET', `/workstations/infra-providers?provider=${provider}`),
  listWsTemplates:       (pid: ParamValue) => req('GET', `/workstations/templates?project_id=${pid}`),
  createWsTemplate:      (data: unknown)   => req('POST', '/workstations/templates', data),
  deleteWsTemplate:      (id: string)      => req('DELETE', `/workstations/templates/${id}`),
  listWorkstations:      (pid: ParamValue) => req('GET', `/workstations?project_id=${pid}`),
  // Workstation pool (PlatformOps providers + user access grants)
  listPoolMachines:      ()                => req('GET',  '/workstations/pool'),
  projectAccessInfo:     (pid: string)     => req('GET',  `/projects/${pid}/access-info`),
  bindPoolMachine:        (id: string, data: unknown) => req('POST', `/workstations/pool/${id}/bind`, data),
  listPoolProviders:     ()                => req('GET',  '/workstations/pool/providers'),
  createPoolMachine:     (data: unknown)   => req('POST', '/workstations/pool', data),
  registerManualMachine: (data: unknown)   => req('POST', '/workstations/pool/x/register-manual', data),
  refreshPoolMachine:    (id: string)      => req('POST', `/workstations/pool/${id}/refresh`),
  testPoolMachine:       (id: string)      => req('POST', `/workstations/pool/${id}/test`),
  setWsExecutor:         (id: string, data: unknown) => req('POST', `/workstations/${id}/executor`, data),
  // Egress proxy pool (admin)
  listProxyEndpoints:    ()                => req('GET',    '/admin/proxies'),
  createProxyEndpoint:   (data: unknown)   => req('POST',   '/admin/proxies', data),
  patchProxyEndpoint:    (id: string, data: unknown) => req('PATCH', `/admin/proxies/${encodeURIComponent(id)}`, data),
  deleteProxyEndpoint:   (id: string)      => req('DELETE', `/admin/proxies/${encodeURIComponent(id)}`),
  checkProxyEndpoint:    (id: string, data?: unknown) => req('POST', `/admin/proxies/${encodeURIComponent(id)}/check`, data || {}),
  listProxyRoutes:       ()                => req('GET',    '/admin/proxies/routes'),
  createProxyRoute:      (data: unknown)   => req('POST',   '/admin/proxies/routes', data),
  patchProxyRoute:       (id: string, data: unknown) => req('PATCH', `/admin/proxies/routes/${encodeURIComponent(id)}`, data),
  deleteProxyRoute:      (id: string)      => req('DELETE', `/admin/proxies/routes/${encodeURIComponent(id)}`),
  proxyResolve:          (category: string, targetRef?: string) => req('GET', `/admin/proxies/resolve?category=${encodeURIComponent(category)}${targetRef ? `&target_ref=${encodeURIComponent(targetRef)}` : ''}`),
  proxyCategories:       ()                => req('GET',    '/admin/proxies/categories'),
  getOutboundProxy:      ()                => req('GET',    '/admin/outbound-proxy'),
  setOutboundProxy:      (data: unknown)   => req('PUT',    '/admin/outbound-proxy', data),
  assignPoolMachine:     (id: string, data: unknown) => req('POST', `/workstations/pool/${id}/assign`, data),
  revokePoolMachine:     (id: string, data: unknown) => req('POST', `/workstations/pool/${id}/revoke`, data),
  myPoolMachines:        ()                => req('GET',  '/workstations/pool/my'),
  userPoolMachines:      (uid: string)     => req('GET',  `/workstations/pool/user/${uid}`),
  mySshKeys:             ()                => req('GET',  '/user/ssh-keys'),
  addMySshKey:           (data: unknown)   => req('POST', '/user/ssh-keys', data),
  deleteMySshKey:        (id: string)      => req('DELETE', `/user/ssh-keys/${id}`),
  userSshKeys:           (uid: string)     => req('GET',  `/admin/users/${uid}/ssh-keys`),
  createWorkstation:     (data: unknown)   => req('POST', '/workstations', data),
  provisionWs:           (id: string)      => req('POST', `/workstations/${id}/provision`),
  destroyWs:             (id: string)      => req('POST', `/workstations/${id}/destroy`),
  getWorkstation:        (id: string)      => req('GET', `/workstations/${id}`),
  deleteWorkstation:     (id: string)      => req('DELETE', `/workstations/${id}`),
  forceDeleteWorkstation:(id: string)      => req('DELETE', `/workstations/${id}/force`),
  updateWorkstation:     (id: string, data: unknown) => req('PATCH', `/workstations/${id}`, data),
  restartWorkstation:    (id: string)      => req('POST', `/workstations/${id}/restart`),
  listWsEvents:          (id: string)      => req('GET', `/workstations/${id}/events`),

  // ── Project Closure ─────────────────────────────────────────────
  closurePreview:        (pid: string)     => req('GET',  `/projects/${pid}/closure-preview`),
  closeProject:          (pid: string, data: unknown) => req('POST', `/projects/${pid}/close`, data),
  archiveProject:        (pid: string)     => req('POST', `/projects/${pid}/archive`),
  getDecommissionReport: (pid: string)     => req('GET',  `/projects/${pid}/decommission-report`),

  // ── Plugins ─────────────────────────────────────────────────────
  listPlugins:           ()                => req('GET', '/plugins'),
  installPlugin:         (data: unknown)   => req('POST', '/plugins/install', data),
  uninstallPlugin:       (id: string)      => req('DELETE', `/plugins/${id}`),
  togglePlugin:          (id: string, data: unknown) => req('PATCH', `/plugins/${id}`, data),

  // ── Marketplace ─────────────────────────────────────────────────
  marketplaceTemplates:  ()                => req('GET', '/marketplace/templates'),
  marketplacePlans:      ()                => req('GET', '/marketplace/plans'),
  marketplaceOrgPlan:    (orgId: string)   => req('GET', `/marketplace/plans/${orgId}`),
  marketplaceUpdatePlan: (orgId: string, data: unknown) => req('PATCH', `/marketplace/plans/${orgId}`, data),

  // ── Organizations ───────────────────────────────────────────────
  listOrganizations:     ()                => req('GET', '/orgs'),
  createOrganization:    (data: unknown)   => req('POST', '/orgs', data),
  getOrganization:       (id: string)      => req('GET', `/orgs/${id}`),
  updateOrganization:    (id: string, data: unknown) => req('PATCH', `/orgs/${id}`, data),
  deleteOrganization:    (id: string)      => req('DELETE', `/orgs/${id}`),
  listOrgMembers:        (orgId: string)   => req('GET', `/orgs/${orgId}/members`),
  addOrgMember:          (orgId: string, data: unknown) => req('POST', `/orgs/${orgId}/members`, data),
  createOrgUser:         (orgId: string, data: unknown) => req('POST', `/orgs/${orgId}/users`, data),
  removeOrgMember:       (orgId: string, uid: string) => req('DELETE', `/orgs/${orgId}/members/${uid}`),
  updateOrgMemberRole:   (orgId: string, uid: string, role: string) => req('PATCH', `/orgs/${orgId}/members/${uid}`, { role }),
  listOrgTeams:          (orgId: string)   => req('GET', `/orgs/${orgId}/teams`),
  createOrgTeam:         (orgId: string, data: unknown) => req('POST', `/orgs/${orgId}/teams`, data),
  deleteOrgTeam:         (orgId: string, teamId: string) => req('DELETE', `/orgs/${orgId}/teams/${teamId}`),
  listTeamMembers:       (orgId: string, teamId: string) => req('GET', `/orgs/${orgId}/teams/${teamId}/members`),
  addTeamMember:         (orgId: string, teamId: string, data: unknown) => req('POST', `/orgs/${orgId}/teams/${teamId}/members`, data),
  removeTeamMember:      (orgId: string, teamId: string, uid: string) => req('DELETE', `/orgs/${orgId}/teams/${teamId}/members/${uid}`),

  // ── OIDC / SSO ──────────────────────────────────────────────────
  listOidcProviders:     (orgId: string) => req('GET', `/orgs/${orgId}/oidc-providers`),
  createOidcProvider:    (orgId: string, data: unknown) => req('POST', `/orgs/${orgId}/oidc-providers`, data),
  updateOidcProvider:    (orgId: string, id: string, data: unknown) => req('PATCH', `/orgs/${orgId}/oidc-providers/${id}`, data),
  deleteOidcProvider:    (orgId: string, id: string) => req('DELETE', `/orgs/${orgId}/oidc-providers/${id}`),
  publicOidcProviders:   (params: { email?: string; org_slug?: string }) => {
    const qs = new URLSearchParams();
    if (params.email) qs.set('email', params.email);
    if (params.org_slug) qs.set('org_slug', params.org_slug);
    return req('GET', `/auth/oidc/providers?${qs.toString()}`, undefined, false);
  },
  oidcLoginUrl:          (providerId: string) => `/api/auth/oidc/${providerId}/login`,
  oidcConfirmLink:       (data: { link_token: string; username: string; password: string }) =>
    req('POST', '/auth/oidc/confirm-link', data, false),

  // ── OIDC / SSO — platform-wide (org_id NULL), platform_admin only ──
  listPlatformOidcProviders:  () => req('GET', '/system/oidc-providers'),
  createPlatformOidcProvider: (data: unknown) => req('POST', '/system/oidc-providers', data),
  updatePlatformOidcProvider: (id: string, data: unknown) => req('PATCH', `/system/oidc-providers/${id}`, data),
  deletePlatformOidcProvider: (id: string) => req('DELETE', `/system/oidc-providers/${id}`),

  // ── Licensing (ФТ-9, docs/modules/LICENSING_TZ.md) ─────────────────
  // Instance-wide, not per-org — a self-hosted install is licensed as a
  // whole (see backend/app/core/license.py's module docstring).
  getLicenseFingerprint: () => req('GET', '/system/license/fingerprint'),
  getActivationRequest:  () => req('GET', '/system/license/activation-request'),
  getLicenseStatus:      () => req('GET', '/system/license/status'),
  getLicenseState:       () => req('GET', '/system/license/state'),
  uploadLicense:         (token: string) => req('POST', '/system/license/upload', { token }),
  checkLicenseNow:       ()                => req('POST', '/system/license/check'),
  setLicenseChannel:     (offline: boolean) => req('PATCH', '/system/license/channel', { offline }),

  // Build edition + entitlement in one call, readable by any user —
  // the navigation is built from it. "ce" means the Enterprise
  // capabilities are not in this build and their endpoints 404, so they
  // are hidden rather than shown with an upgrade prompt.
  getEdition:            () => req('GET', '/system/edition'),

  // ── Project teams ─────────────────────────────────────────────────
  attachTeamToProject:   (pid: string, teamId: string)  => req('POST',   `/projects/${pid}/teams`, { team_id: teamId }),
  detachTeamFromProject: (pid: string, teamId: string)  => req('DELETE', `/projects/${pid}/teams/${teamId}`),
  listProjectTeams:      (pid: string)                   => req('GET',    `/projects/${pid}/teams`),

  // ── Encryption ──────────────────────────────────────────────────
  listEncryptionKeys:    (pid: ParamValue) => req('GET', `/system/encryption/keys?project_id=${pid}`),
  rotateDEK:             (pid: string)     => req('POST', `/system/encryption/rotate-dek?project_id=${pid}`),

  // ── Secrets Vault ───────────────────────────────────────────────
  listSecrets:           (pid: string)     => req('GET', `/projects/${pid}/secrets`),
  createSecret:          (pid: string, data: unknown) => req('POST', `/projects/${pid}/secrets`, data),
  getSecret:             (pid: string, sid: string) => req('GET', `/projects/${pid}/secrets/${sid}`),
  updateSecret:          (pid: string, sid: string, data: unknown) => req('PATCH', `/projects/${pid}/secrets/${sid}`, data),
  deleteSecret:          (pid: string, sid: string) => req('DELETE', `/projects/${pid}/secrets/${sid}`),
  revokeSecret:          (pid: string, sid: string) => req('POST', `/projects/${pid}/secrets/${sid}/revoke`),
  generateSSHKey:        (pid: string, data: unknown) => req('POST', `/projects/${pid}/secrets/generate-ssh`, data),

  // ── Members & Invitations ───────────────────────────────────────
  listProjectMembers:    (pid: string)     => req('GET', `/projects/${pid}/members`),
  updateMemberRole:      (pid: string, uid: string, data: unknown) => req('PATCH', `/projects/${pid}/members/${uid}`, data),
  listAvailableUsers:    (pid: string)     => req('GET', `/projects/${pid}/available-users`),
  getMyPermissions:      (pid: string)     => req('GET', `/projects/${pid}/permissions/me`),
  createInvitation:      (pid: string, data: unknown) => req('POST', `/projects/${pid}/invitations`, data),
  listInvitations:       (pid: string)     => req('GET', `/projects/${pid}/invitations`),
  revokeInvitation:      (pid: string, invId: string) => req('POST', `/projects/${pid}/invitations/${invId}/revoke`),

  // ── ROE ───────────────────────────────────────────────────────────
  getROE:                (pid: string)     => req('GET', `/projects/${pid}/roe`),
  upsertROE:             (pid: string, data: unknown) => req('PUT', `/projects/${pid}/roe`, data),
  deleteROE:             (pid: string)     => req('DELETE', `/projects/${pid}/roe`),

  // ── System Panel ──────────────────────────────────────────────────
  getSystemHealth:       ()                => req('GET', '/system/health'),
  getSystemLogs:         (params?: string) => req('GET', `/system/logs${params ? '?' + params : ''}`),
  getSystemMetrics:      ()                => req('GET', '/system/metrics'),
  getHAStatus:           ()                => req('GET', '/system/ha'),
  getSystemModules:      ()                => req('GET', '/system/modules'),

  // ── Instance Pool ────────────────────────────────────────────────
  getInstanceTemplates:        (serviceType?: string) => req('GET', `/instance-templates${serviceType ? '?service_type=' + serviceType : ''}`),
  createInstanceTemplate:      (data: unknown)        => req('POST', '/instance-templates', data),
  getInstanceTemplate:         (id: string)           => req('GET', `/instance-templates/${id}`),
  updateInstanceTemplate:      (id: string, data: unknown) => req('PUT', `/instance-templates/${id}`, data),
  deleteInstanceTemplate:      (id: string)           => req('DELETE', `/instance-templates/${id}`),
  getTemplatePoolStats:        (id: string)           => req('GET', `/instance-templates/${id}/pool-stats`),

  getManagedInstances:         (params?: string)      => req('GET', `/managed-instances${params ? '?' + params : ''}`),
  getInstancePool:             (templateId?: string)  => req('GET', `/managed-instances/pool${templateId ? '?template_id=' + templateId : ''}`),
  provisionInstances:          (data: unknown)        => req('POST', '/managed-instances/provision', data),
  claimInstance:               (id: string, data: unknown) => req('POST', `/managed-instances/${id}/claim`, data),
  releaseInstance:             (id: string)           => req('POST', `/managed-instances/${id}/release`),
  reconfigInstance:            (id: string)           => req('POST', `/managed-instances/${id}/reconfig`),
  syncInstanceUsers:           (id: string)           => req('POST', `/managed-instances/${id}/sync-users`),
  getInstanceStatus:           (id: string)           => req('GET', `/managed-instances/${id}/status`),
  destroyInstance:             (id: string)           => req('DELETE', `/managed-instances/${id}`),

  getInstanceCredentials:      (params?: string)      => req('GET', `/instance-credentials${params ? '?' + params : ''}`),
  getMyCredentials:            (projectId?: string)   => req('GET', `/instance-credentials/my${projectId ? '?project_id=' + projectId : ''}`),
  revokeCredential:            (id: string)           => req('DELETE', `/instance-credentials/${id}`),

  // ── Infrastructure V2 ────────────────────────────────────────────
  getInfraPresets:             ()                     => req('GET', '/infra-v2/presets'),
  getInfraProviders:           ()                     => req('GET', '/infra-v2/providers'),
  createInfraProvider:         (data: unknown)        => req('POST', '/infra-v2/providers', data),
  updateInfraProvider:         (id: string, data: unknown) => req('PATCH', `/infra-v2/providers/${id}`, data),
  deleteInfraProvider:         (id: string)           => req('DELETE', `/infra-v2/providers/${id}`),
  checkInfraProvider:          (id: string)           => req('POST', `/infra-v2/providers/${id}/check`),
  testInfraProvider:           (data: unknown)        => req('POST', '/infra-v2/providers/test', data),
  provisionNodeFromProvider:   (id: string, data: unknown) => req('POST', `/infra-v2/providers/${id}/provision-node`, data),

  getInfraNodes:               (params?: string)      => req('GET', `/infra-v2/nodes${params ? '?' + params : ''}`),
  getInfraNode:                (id: string)           => req('GET', `/infra-v2/nodes/${id}`),
  createInfraNode:             (data: unknown)        => req('POST', '/infra-v2/nodes', data),
  updateInfraNode:             (id: string, data: unknown) => req('PATCH', `/infra-v2/nodes/${id}`, data),
  checkInfraNode:              (id: string)           => req('POST', `/infra-v2/nodes/${id}/check`),
  deleteInfraNode:             (id: string)           => req('DELETE', `/infra-v2/nodes/${id}`),

  getV2Templates:              (type?: string)        => req('GET', `/infra-v2/templates${type ? '?type=' + type : ''}`),
  getV2Template:               (id: string)           => req('GET', `/infra-v2/templates/${id}`),
  createV2Template:            (data: unknown)        => req('POST', '/infra-v2/templates', data),
  updateV2Template:            (id: string, data: unknown) => req('PATCH', `/infra-v2/templates/${id}`, data),
  deleteV2Template:            (id: string)           => req('DELETE', `/infra-v2/templates/${id}`),

  getInfraBlueprints:          ()                     => req('GET', '/infra-v2/blueprints'),
  createInfraBlueprint:        (data: unknown)        => req('POST', '/infra-v2/blueprints', data),
  updateInfraBlueprint:        (id: string, data: unknown) => req('PATCH', `/infra-v2/blueprints/${id}`, data),
  deleteInfraBlueprint:        (id: string)           => req('DELETE', `/infra-v2/blueprints/${id}`),

  getInfraStacks:              (params?: string)      => req('GET', `/infra-v2/stacks${params ? '?' + params : ''}`),
  deployInfraStack:            (data: unknown)        => req('POST', '/infra-v2/stacks/deploy', data),
  previewStack:                (data: unknown)        => req('POST', '/infra-v2/stacks/preview', data),
  getInfraStack:               (id: string)           => req('GET', `/infra-v2/stacks/${id}`),
  checkStackHealth:            (id: string)           => req('POST', `/infra-v2/stacks/${id}/health-check`),
  redeployService:             (sid: string, ssid: string) => req('POST', `/infra-v2/stacks/${sid}/services/${ssid}/redeploy`),
  rollbackService:             (sid: string, ssid: string) => req('POST', `/infra-v2/stacks/${sid}/services/${ssid}/rollback`),
  bindInfraStack:              (id: string, data: unknown) => req('POST', `/infra-v2/stacks/${id}/bind`, data),
  destroyInfraStack:           (id: string)           => req('DELETE', `/infra-v2/stacks/${id}`),

  getStackStatus:              (sid: string)          => req('GET', `/infra-v2/stacks/${sid}/status`),

  getStackServices:            (sid: string)          => req('GET', `/infra-v2/stacks/${sid}/services`),
  checkServiceHealth:          (sid: string, ssid: string) => req('POST', `/infra-v2/stacks/${sid}/services/${ssid}/health`),
  reconfigService:             (sid: string, ssid: string, data: unknown) => req('POST', `/infra-v2/stacks/${sid}/services/${ssid}/reconfig`, data),

  getStackLinks:               (sid: string)          => req('GET', `/infra-v2/stacks/${sid}/links`),
  verifyLink:                  (sid: string, lid: string) => req('POST', `/infra-v2/stacks/${sid}/links/${lid}/verify`),

  getStackCredentials:         (sid: string)          => req('GET', `/infra-v2/stacks/${sid}/credentials`),
  createStackCredential:       (sid: string, data: unknown) => req('POST', `/infra-v2/stacks/${sid}/credentials`, data),

  getStackAgents:              (sid: string)          => req('GET', `/infra-v2/stacks/${sid}/agents`),
  generateAgent:               (sid: string, data: unknown) => req('POST', `/infra-v2/stacks/${sid}/agents/generate`, data),

  getStackFiles:               (sid: string)          => req('GET', `/infra-v2/stacks/${sid}/files`),
  createFileShare:             (sid: string, data: unknown) => req('POST', `/infra-v2/stacks/${sid}/files`, data),

  getStackOperators:           (sid: string)          => req('GET', `/infra-v2/stacks/${sid}/operators`),
  grantOperator:               (sid: string, data: unknown) => req('POST', `/infra-v2/stacks/${sid}/operators/grant`, data),
  revokeOperator:              (sid: string, uid: string) => req('DELETE', `/infra-v2/stacks/${sid}/operators/${uid}`),

  getProjectInfraCreds:        (pid: string)          => req('GET', `/infra-v2/projects/${pid}/infra/creds`),

  getDeploySteps:              (sid: string)          => req('GET', `/infra-v2/stacks/${sid}/steps`),
  applyStackChanges:           (sid: string, data: unknown) => req('POST', `/infra-v2/stacks/${sid}/apply`, data),
  getProviderModes:            ()                     => req('GET', '/infra-v2/providers/modes'),

  // ── Provider & Method Catalog (new architecture) ─────────────────
  getProviderCatalog:          ()                     => req('GET', '/infra-v2/providers/catalog'),
  getProviderSchema:           (ptype: string)        => req('GET', `/infra-v2/providers/${ptype}/schema`),
  getDeployMethods:            ()                     => req('GET', '/infra-v2/deploy-methods'),
  getMethodsForProvider:       (ptype: string)        => req('GET', `/infra-v2/deploy-methods/for/${ptype}`),
  getCompatibilityMatrix:      ()                     => req('GET', '/infra-v2/compatibility'),
  previewServiceDeploy:        (sid: string, ssid: string) => req('POST', `/infra-v2/stacks/${sid}/services/${ssid}/preview`),
  getServiceLogs:              (sid: string, ssid: string, tail?: number) => req('GET', `/infra-v2/stacks/${sid}/services/${ssid}/logs${tail ? '?tail=' + tail : ''}`),

  discoverServices:            (sid: string)          => req('POST', `/infra-v2/stacks/${sid}/discover`),
  verifyAllLinks:              (sid: string)          => req('POST', `/infra-v2/stacks/${sid}/links/verify-all`),

  unbindInfraStack:            (id: string)           => req('POST', `/infra-v2/stacks/${id}/unbind`),
  integrateStack:              (id: string)           => req('POST', `/infra-v2/stacks/${id}/integrate`),

  getDevOpsLog:                (params?: string)      => req('GET', `/devops-log${params ? '?' + params : ''}`),
  wsActionsFeed:               (limit = 100)        => req('GET', `/workstations/actions-feed?limit=${limit}`),
  clearDevOpsLog:              (params?: string)      => req('DELETE', `/devops-log${params ? '?' + params : ''}`),

  getPlatformApiUrl:           ()                     => req('GET', '/infra-v2/platform-api-url'),
  updatePlatformApiUrl:        (data: unknown)        => req('PUT', '/infra-v2/platform-api-url', data),

  // ── DNS ──────────────────────────────────────────────────────────

  getDnsZones:                 (providerId?: string)  => req('GET', `/infra-v2/dns/zones${providerId ? '?provider_id=' + providerId : ''}`),
  syncDnsZones:                (pid: string)          => req('POST', `/infra-v2/dns/providers/${pid}/zones/sync`),
  updateDnsZone:               (zid: string, data: unknown) => req('PATCH', `/infra-v2/dns/zones/${zid}`, data),
  getDnsRecords:               (zid: string, remote?: boolean) => req('GET', `/infra-v2/dns/zones/${zid}/records${remote ? '?remote=true' : ''}`),
  createDnsRecord:             (zid: string, data: unknown) => req('POST', `/infra-v2/dns/zones/${zid}/records`, data),
  updateDnsRecord:             (rid: string, data: unknown) => req('PATCH', `/infra-v2/dns/records/${rid}`, data),
  deleteDnsRecord:             (rid: string)          => req('DELETE', `/infra-v2/dns/records/${rid}`),
  checkDnsRecordStatus:        (rid: string)          => req('GET', `/infra-v2/dns/records/${rid}/status`),
  checkDnsPropagation:         (rid: string)          => req('POST', `/infra-v2/dns/records/${rid}/check-propagation`),
  checkDnsZoneExpiration:      (zid: string)          => req('POST', `/infra-v2/dns/zones/${zid}/check-expiration`),
  getExpiringDnsZones:         (days?: number)        => req('GET', `/infra-v2/dns/zones/expiring${days ? '?days=' + days : ''}`),

  // ── SSL / Let's Encrypt ──────────────────────────────────────────
  listSslCerts:                (params?: Record<string, unknown>) => {
    const qs = new URLSearchParams(params as Record<string, string>).toString();
    return req('GET', `/infra-v2/ssl/certificates${qs ? '?' + qs : ''}`);
  },
  getSslCert:                  (id: string)           => req('GET', `/infra-v2/ssl/certificates/${id}`),
  issueSslCert:                (data: unknown)        => req('POST', `/infra-v2/ssl/certificates`, data),
  renewSslCert:                (id: string)           => req('POST', `/infra-v2/ssl/certificates/${id}/renew`),
  deleteSslCert:               (id: string)           => req('DELETE', `/infra-v2/ssl/certificates/${id}`),
  downloadSslCert:             (id: string, format?: string) => download(`/infra-v2/ssl/certificates/${id}/download${format ? '?format=' + format : ''}`),

  getAllDnsRecords:            (params?: Record<string, unknown>) => {
    const qs = new URLSearchParams(params as Record<string, string>).toString();
    return req('GET', `/infra-v2/dns/records${qs ? '?' + qs : ''}`);
  },

  // ── VPN (WireGuard) ──────────────────────────────────────────────

  getVpnStatus:               (pid: string)          => req('GET', `/infra-v2/providers/${pid}/vpn/status`),
  setupVpn:                   (pid: string)          => req('POST', `/infra-v2/providers/${pid}/vpn/setup`),
  createVpnClient:            (pid: string, data: unknown) => req('POST', `/infra-v2/providers/${pid}/vpn/clients`, data),
  listVpnClients:             (pid: string)          => req('GET', `/infra-v2/providers/${pid}/vpn/clients`),
  deleteVpnClient:            (pid: string, name: string) => req('DELETE', `/infra-v2/providers/${pid}/vpn/clients/${name}`),

  // ── Extension Modules ────────────────────────────────────────────

  listExtModules:             ()                     => req('GET', '/modules'),
  enableExtModule:            (id: string)           => req('POST', `/modules/${id}/enable`),
  disableExtModule:           (id: string)           => req('POST', `/modules/${id}/disable`),
  extModuleHealth:            (id: string)           => req('GET', `/modules/${id}/health`),
  listObjectTypes:            ()                     => req('GET', '/modules/object-types'),
  getObjectSchema:            (type: string)         => req('GET', `/modules/object-types/${type}`),
  listExtensions:             ()                     => req('GET', '/modules/extensions'),
  getExtensions:              (point: string)        => req('GET', `/modules/extensions/${point}`),
  listObjects:                (params?: Record<string, unknown>) => {
    const qs = new URLSearchParams(params as Record<string, string>).toString();
    return req('GET', `/modules/objects${qs ? '?' + qs : ''}`);
  },
  createObject:               (data: unknown)        => req('POST', '/modules/objects', data),
  getObject:                  (id: string)           => req('GET', `/modules/objects/${id}`),
  updateObject:               (id: string, data: unknown) => req('PATCH', `/modules/objects/${id}`, data),
  deleteObject:               (id: string)           => req('DELETE', `/modules/objects/${id}`),
  addObjectRelation:          (id: string, data: unknown) => req('POST', `/modules/objects/${id}/relations`, data),
  getObjectRelations:         (id: string, relType: string) => req('GET', `/modules/objects/${id}/relations/${relType}`),
};

/** Returns the URL unchanged — cookie auth handles authentication for download links. */
export function downloadUrl(url: string | null | undefined): string {
  return url || '';
}

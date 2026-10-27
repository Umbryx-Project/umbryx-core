"""pid indexes: btree on every project-scoped table (release 1.0.0 audit)

`WHERE pid = ...` is the single most common filter in the platform (every
router scopes by project first), but only 5 of 49 pid columns were indexed
— the rest full-scanned. Aligns the DB schema with the models, which now
carry index=True on every pid column uniformly (fresh installs get these
via create_all; existing deployments via this migration).

Revision ID: 089
Revises: 088
"""

from alembic import op

revision = "089"
down_revision = "088"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_attack_path_branches_pid", "attack_path_branches", ["pid"], if_not_exists=True)
    op.create_index("ix_attack_path_edges_pid", "attack_path_edges", ["pid"], if_not_exists=True)
    op.create_index("ix_attack_path_nodes_pid", "attack_path_nodes", ["pid"], if_not_exists=True)
    op.create_index("ix_attack_paths_pid", "attack_paths", ["pid"], if_not_exists=True)
    op.create_index("ix_checklist_items_pid", "checklist_items", ["pid"], if_not_exists=True)
    op.create_index("ix_conflict_records_pid", "conflict_records", ["pid"], if_not_exists=True)
    op.create_index("ix_cred_host_notes_pid", "cred_host_notes", ["pid"], if_not_exists=True)
    op.create_index("ix_creds_pid", "creds", ["pid"], if_not_exists=True)
    op.create_index("ix_entity_links_pid", "entity_links", ["pid"], if_not_exists=True)
    op.create_index("ix_evidence_pid", "evidence", ["pid"], if_not_exists=True)
    op.create_index("ix_findings_pid", "findings", ["pid"], if_not_exists=True)
    op.create_index("ix_firewall_config_uploads_pid", "firewall_config_uploads", ["pid"], if_not_exists=True)
    op.create_index("ix_host_activities_pid", "host_activities", ["pid"], if_not_exists=True)
    op.create_index("ix_host_claims_pid", "host_claims", ["pid"], if_not_exists=True)
    op.create_index("ix_host_collections_pid", "host_collections", ["pid"], if_not_exists=True)
    op.create_index("ix_hosts_pid", "hosts", ["pid"], if_not_exists=True)
    op.create_index("ix_identities_pid", "identities", ["pid"], if_not_exists=True)
    op.create_index("ix_jobs_pid", "jobs", ["pid"], if_not_exists=True)
    op.create_index("ix_kb_articles_pid", "kb_articles", ["pid"], if_not_exists=True)
    op.create_index("ix_loots_pid", "loots", ["pid"], if_not_exists=True)
    op.create_index("ix_metric_snapshots_pid", "metric_snapshots", ["pid"], if_not_exists=True)
    op.create_index("ix_network_edges_pid", "network_edges", ["pid"], if_not_exists=True)
    op.create_index("ix_network_nodes_pid", "network_nodes", ["pid"], if_not_exists=True)
    op.create_index("ix_network_regions_pid", "network_regions", ["pid"], if_not_exists=True)
    op.create_index("ix_networks_pid", "networks", ["pid"], if_not_exists=True)
    op.create_index("ix_note_attachments_pid", "note_attachments", ["pid"], if_not_exists=True)
    op.create_index("ix_notes_pid", "notes", ["pid"], if_not_exists=True)
    op.create_index("ix_objectives_pid", "objectives", ["pid"], if_not_exists=True)
    op.create_index("ix_pb_automations_pid", "pb_automations", ["pid"], if_not_exists=True)
    op.create_index("ix_pb_runs_v2_pid", "pb_runs_v2", ["pid"], if_not_exists=True)
    op.create_index("ix_pivot_observations_pid", "pivot_observations", ["pid"], if_not_exists=True)
    op.create_index("ix_playbook_runs_pid", "playbook_runs", ["pid"], if_not_exists=True)
    op.create_index("ix_project_domains_pid", "project_domains", ["pid"], if_not_exists=True)
    op.create_index("ix_project_snapshots_pid", "project_snapshots", ["pid"], if_not_exists=True)
    op.create_index("ix_remediations_pid", "remediations", ["pid"], if_not_exists=True)
    op.create_index("ix_saved_searches_pid", "saved_searches", ["pid"], if_not_exists=True)
    op.create_index("ix_scan_snapshots_pid", "scan_snapshots", ["pid"], if_not_exists=True)
    op.create_index("ix_scheduled_playbooks_pid", "scheduled_playbooks", ["pid"], if_not_exists=True)
    op.create_index("ix_scopes_pid", "scopes", ["pid"], if_not_exists=True)
    op.create_index("ix_sync_events_pid", "sync_events", ["pid"], if_not_exists=True)
    op.create_index("ix_sync_state_pid", "sync_state", ["pid"], if_not_exists=True)
    op.create_index("ix_tasks_pid", "tasks", ["pid"], if_not_exists=True)
    op.create_index("ix_timeline_events_pid", "timeline_events", ["pid"], if_not_exists=True)
    op.create_index("ix_workstation_actions_pid", "workstation_actions", ["pid"], if_not_exists=True)


def downgrade() -> None:
    op.drop_index("ix_workstation_actions_pid", table_name="workstation_actions")
    op.drop_index("ix_timeline_events_pid", table_name="timeline_events")
    op.drop_index("ix_tasks_pid", table_name="tasks")
    op.drop_index("ix_sync_state_pid", table_name="sync_state")
    op.drop_index("ix_sync_events_pid", table_name="sync_events")
    op.drop_index("ix_scopes_pid", table_name="scopes")
    op.drop_index("ix_scheduled_playbooks_pid", table_name="scheduled_playbooks")
    op.drop_index("ix_scan_snapshots_pid", table_name="scan_snapshots")
    op.drop_index("ix_saved_searches_pid", table_name="saved_searches")
    op.drop_index("ix_remediations_pid", table_name="remediations")
    op.drop_index("ix_project_snapshots_pid", table_name="project_snapshots")
    op.drop_index("ix_project_domains_pid", table_name="project_domains")
    op.drop_index("ix_playbook_runs_pid", table_name="playbook_runs")
    op.drop_index("ix_pivot_observations_pid", table_name="pivot_observations")
    op.drop_index("ix_pb_runs_v2_pid", table_name="pb_runs_v2")
    op.drop_index("ix_pb_automations_pid", table_name="pb_automations")
    op.drop_index("ix_objectives_pid", table_name="objectives")
    op.drop_index("ix_notes_pid", table_name="notes")
    op.drop_index("ix_note_attachments_pid", table_name="note_attachments")
    op.drop_index("ix_networks_pid", table_name="networks")
    op.drop_index("ix_network_regions_pid", table_name="network_regions")
    op.drop_index("ix_network_nodes_pid", table_name="network_nodes")
    op.drop_index("ix_network_edges_pid", table_name="network_edges")
    op.drop_index("ix_metric_snapshots_pid", table_name="metric_snapshots")
    op.drop_index("ix_loots_pid", table_name="loots")
    op.drop_index("ix_kb_articles_pid", table_name="kb_articles")
    op.drop_index("ix_jobs_pid", table_name="jobs")
    op.drop_index("ix_identities_pid", table_name="identities")
    op.drop_index("ix_hosts_pid", table_name="hosts")
    op.drop_index("ix_host_collections_pid", table_name="host_collections")
    op.drop_index("ix_host_claims_pid", table_name="host_claims")
    op.drop_index("ix_host_activities_pid", table_name="host_activities")
    op.drop_index("ix_firewall_config_uploads_pid", table_name="firewall_config_uploads")
    op.drop_index("ix_findings_pid", table_name="findings")
    op.drop_index("ix_evidence_pid", table_name="evidence")
    op.drop_index("ix_entity_links_pid", table_name="entity_links")
    op.drop_index("ix_creds_pid", table_name="creds")
    op.drop_index("ix_cred_host_notes_pid", table_name="cred_host_notes")
    op.drop_index("ix_conflict_records_pid", table_name="conflict_records")
    op.drop_index("ix_checklist_items_pid", table_name="checklist_items")
    op.drop_index("ix_attack_paths_pid", table_name="attack_paths")
    op.drop_index("ix_attack_path_nodes_pid", table_name="attack_path_nodes")
    op.drop_index("ix_attack_path_edges_pid", table_name="attack_path_edges")
    op.drop_index("ix_attack_path_branches_pid", table_name="attack_path_branches")

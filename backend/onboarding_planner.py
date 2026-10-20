"""Stag Prime Sentinel Step 37.12 — pure, read-only setup recommendation planner.

Consumes ONLY the already-sanitized preflight payload and the cached operator-
initiated discovery snapshot. Never opens SSH, executes commands or writes to DB.
There is deliberately no installation / approval / restart API in this module.
Unknown evidence fails closed; an absent service string does not prove fresh VPS.
"""
from __future__ import annotations

from typing import Any


# All client-visible suggestions are fixed author-controlled text, not shell code.
# The user-facing UI cannot be used to execute these steps remotely.
def _item(code: str, title: str, guidance: str, *, impact: str = 'review') -> dict[str, str]:
    return {'code': code, 'title': title, 'guidance': guidance, 'impact': impact}


def build_setup_plan(entry: dict[str, Any]) -> dict[str, Any]:
    """Build a conservative review-only plan for one inventory record.

    The caller must pass a per-server preflight entry, possibly containing a
    cached public discovery snapshot. No secrets, SSH paths or VPN client
    details are used or returned. Do not infer fresh installation from silence.
    """
    phase = entry.get('phase')
    checks = entry.get('checks') if isinstance(entry.get('checks'), dict) else {}
    discovery = entry.get('discovery') if isinstance(entry.get('discovery'), dict) else None
    state = discovery.get('state') if discovery else None
    scan = entry.get('onboarding_scan') if isinstance(entry.get('onboarding_scan'), dict) else None
    scan_state = scan.get('state') if scan else None
    scan_classification = scan.get('classification') if scan_state == 'success' else None
    admin_ready = bool(checks.get('admin_credential_ready'))
    observation = discovery.get('observation') if discovery and isinstance(discovery.get('observation'), dict) else {}
    vpn_service = observation.get('vpn_service')
    status_access = observation.get('status_access')
    interface = observation.get('vpn_interface')

    status = 'review_required'
    template = 'undetermined'
    title = 'Assessment required'
    summary = 'No changes can be proposed safely until the existing server configuration is verified.'
    impact = 'None — plan only'
    maintenance_window = False
    actions: list[dict[str, str]] = []
    blockers: list[str] = []

    if phase == 'inventory_incomplete' or not checks.get('inventory_identity_complete', False):
        status = 'blocked'
        template = 'inventory'
        title = 'Complete server inventory'
        summary = 'The SSH target is not sufficiently identified. Remote discovery is blocked.'
        actions = [
            _item('inventory', 'Complete the server identity', 'Confirm client ownership, IP or DNS, SSH account and port in Server Inventory.'),
            _item('ownership', 'Confirm operating authorization', 'Obtain written client authorization and define who may approve maintenance.'),
            _item('enroll', 'Enroll trusted access later', 'Set up pinned host-key verification and an approved least-privilege SSH account before probing.'),
        ]
        blockers = ['Incomplete SSH inventory', 'No remote action approved']
    elif phase == 'approval_required' or not (checks.get('monitoring_profile_approved', False) or admin_ready):
        status = 'blocked'
        template = 'access_approval'
        title = 'SSH enrollment & approval required'
        summary = 'Inventory alone does not authorize Sentinel to contact a client server.'
        actions = [
            _item('permission', 'Obtain client authorization', 'Verify server ownership, intended monitoring scope and the responsible administrator.'),
            _item('host', 'Verify SSH host identity', 'Enroll host-key trust out of band and pin the authorized endpoint.'),
            _item('profile', 'Approve monitoring profile locally', 'Use the protected local monitoring enrollment process; do not put private keys or passwords in the browser.'),
            _item('discover', 'Run read-only discovery', 'After approval, run the explicitly confirmed CLI probe and refresh this page.', impact='read_only'),
        ]
        blockers = ['No approved remote SSH profile']
    elif phase == 'configuration_attention' or not checks.get('local_configuration_ready', False):
        status = 'blocked'
        template = 'local_profile'
        title = 'Repair local monitoring profile'
        summary = 'The locally approved profile is incomplete, unavailable or does not match current inventory.'
        actions = [
            _item('pin', 'Review approved endpoint', 'Verify the pinned host, SSH port and username still match inventory; do not silently approve a changed host.'),
            _item('key', 'Verify protected SSH files', 'Check that the backend can access the administrator-approved key and host trust files. Never upload secrets to the frontend.'),
            _item('approve', 'Re-approve changes if necessary', 'Any changed endpoint or access identity requires a new explicit administrator authorization.'),
            _item('discover', 'Run approved read-only discovery', 'Re-run the confirmed SSH probe once the local profile is ready.', impact='read_only'),
        ]
        blockers = ['Local SSH profile not ready']
    elif scan_classification in ('fresh_candidate', 'needs_review', 'openvpn_detected', 'openvpn_service_active'):
        status = 'review_required' if scan_classification in ('fresh_candidate', 'needs_review') else 'monitoring_prepared'
        template = 'verified_ssh_scan'
        title = ('Fresh installation candidate — confirm recovery and workloads' if scan_classification == 'fresh_candidate'
                 else 'Manual service review required' if scan_classification == 'needs_review'
                 else 'Existing OpenVPN components detected')
        summary = str(scan.get('next_step') or 'Review the recent audited read-only scan before proposing changes.')[:500]
        actions = [
            _item('review', 'Review verified server scan', 'Check OS, package evidence, service units and other VPN deployments before approving an action.', impact='read_only'),
            _item('recovery', 'Prepare a recovery baseline', 'Confirm cloud snapshot, SSH recovery and client maintenance authorization before installation or repair.'),
            _item('approve', 'Request installation approval separately', 'The discovery result is not permission to install packages, open ports or restart VPN services.'),
        ]
        blockers = ['Privileged installation has not been approved or implemented']
        maintenance_window = True
        impact = 'No remote change in this stage'
    elif scan_state in ('error', 'stale') and (state is None or state != 'success'):
        status = 'blocked' if scan_state == 'error' else 'needs_discovery'
        template = 'scan_failure' if scan_state == 'error' else 'scan_stale'
        title = 'Read-only SSH scan needs attention' if scan_state == 'error' else 'Read-only SSH scan expired'
        summary = 'No current classification is available. Review host trust and approved SSH access before retrying.'
        actions = [_item('retry', 'Retry verified read-only scan', 'Review SSH trust, then use the approved Scan server action.', impact='read_only')]
        blockers = ['No recent successful verified classification']
    elif state is None:
        status = 'needs_discovery'
        template = 'awaiting_discovery'
        title = 'Read-only discovery pending'
        summary = 'Local credentials are approved, but no valid SSH discovery report is available yet.'
        actions = [
            _item('probe', 'Run approved discovery', 'Use the local confirmed read-only discovery command and refresh the dashboard.', impact='read_only'),
            _item('inspect', 'Review environment', 'Confirm OS, OpenVPN instance, tunnel, WAN interface and VPN status-file access from the observation.'),
            _item('classify', 'Classify fresh or existing installation', 'Only after positive evidence, choose a fresh-install or existing-server maintenance playbook.'),
        ]
        blockers = ['No recent verified discovery report']
    elif state == 'stale':
        status = 'needs_discovery'
        template = 'stale_snapshot'
        title = 'Discovery expired — refresh first'
        summary = 'An old snapshot cannot authorize configuration changes or establish current service state.'
        actions = [
            _item('recheck', 'Refresh SSH discovery', 'Use the explicit read-only local CLI; then reload this page.', impact='read_only'),
            _item('compare', 'Compare observations', 'Review instance name, tunnel and status access against the earlier observation.'),
        ]
        blockers = ['Discovery snapshot expired']
    elif state == 'error':
        status = 'blocked'
        template = 'ssh_connectivity'
        title = 'SSH discovery needs investigation'
        summary = 'The approved read-only probe could not complete. Do not assume a VPN outage.'
        actions = [
            _item('trust', 'Review SSH host trust and credentials', 'Verify pinned host identity, authorization, port and access without weakening host-key checks.'),
            _item('network', 'Review reachability', 'Check cloud firewall and provider console out of band before repeating the probe.'),
            _item('retry', 'Repeat the approved probe', 'Run the local read-only discovery command after resolving access issues.', impact='read_only'),
        ]
        blockers = ['SSH discovery failed']
    elif state == 'success' and (not isinstance(vpn_service, str) or not vpn_service.strip()):
        status = 'review_required'
        template = 'service_not_detected'
        title = 'OpenVPN service not verified'
        summary = 'The probe did not identify one validated OpenVPN service. This alone does not prove the VPS is fresh.'
        actions = [
            _item('inventory', 'Confirm existing services and clients', 'Check for alternate instances, containers, firewall rules, VPN profiles and other workloads before any install.'),
            _item('classify', 'Choose the correct playbook', 'If the VPS is confirmed fresh and the client authorizes deployment, use the CE Installation Center; otherwise investigate the existing VPN.'),
            _item('backup', 'Capture a recovery baseline', 'Before any eventual deployment, arrange OS snapshot, access recovery and maintenance approval.'),
        ]
        blockers = ['Existing VPN state not positively identified']
        maintenance_window = True
        impact = 'Possible downtime — only after a separate approved installation phase'
    elif state == 'success' and status_access == 'readable':
        status = 'monitoring_prepared'
        template = 'operational'
        title = 'Monitoring status file accessible'
        summary = 'A recent cached SSH observation reports a running OpenVPN instance with readable status information.'
        actions = [
            _item('health', 'Verify live session API', 'Check the server health endpoint for a non-null connection count, available state and fresh status age.', impact='read_only'),
            _item('validate', 'Verify VPN function independently', 'Confirm authorized client traffic, DNS and reconnection behaviour before reporting production readiness.'),
            _item('record', 'Plan historical telemetry', 'Session history and per-user public IP reporting need separate collection, retention and access controls.'),
        ]
        blockers = ['No installation or restart approval implied by this result']
    elif state == 'success' and status_access == 'permission_required':
        status = 'review_required'
        template = 'status_permissions'
        title = 'VPN status file access needs review'
        summary = 'OpenVPN was discovered, but the approved SSH monitoring user cannot read the required status information.'
        actions = [
            _item('inspect', 'Inspect the active instance and status path', 'Verify the effective OpenVPN config, actual status file owner and privileges using approved administrator access; do not guess a path.'),
            _item('least', 'Design least-privilege read access', 'Prefer a narrowly scoped ACL or an approved status reader. Avoid global chmod 777, root SSH and unrestricted sudo.'),
            _item('backup', 'Back up before changing settings', 'Take a dated configuration backup and confirm a recovery path. File-permission fixes may not require a restart.'),
            _item('authorize', 'Get separate change approval', 'Require authenticated administrator approval, audit and maintenance scheduling if service config or restart is needed.'),
            _item('verify', 'Re-probe and verify sessions', 'After operator-approved remediation, repeat SSH discovery and confirm the live API reports available sessions.', impact='read_only'),
        ]
        blockers = ['Monitoring account has no verified status-file access', 'Remote changes are disabled']
        maintenance_window = True
        impact = 'Potential restart only if server configuration must change'
    else:
        status = 'review_required'
        template = 'status_unknown'
        title = 'OpenVPN status source needs verification'
        summary = 'OpenVPN was discovered, but the cached read-only data does not confirm usable status-file access.'
        actions = [
            _item('source', 'Identify the active instance and its status source', 'Confirm one exact running instance and inspect its configured status directive and freshness.'),
            _item('review', 'Determine whether a file or permission change is needed', 'Do not treat unknown or missing data as zero sessions. Confirm status version and protected access.'),
            _item('backup', 'Prepare a rollback plan', 'Take a dated backup and schedule any changes requiring a VPN restart.'),
            _item('approve', 'Request authenticated change approval later', 'Wait for implemented Admin login, RBAC, audit logs and explicit approval. The current API cannot change a server.'),
        ]
        blockers = ['Session monitoring source unverified', 'Remote changes are disabled']
        maintenance_window = True
        impact = 'Possible downtime — only with a separately approved change'

    # Plan data is intentionally immutable public guidance. No credentials or
    # untrusted remote diagnostic text flow into titles, notes or actions.
    return {
        'version': 1,
        'status': status,
        'template': template,
        'title': title,
        'summary': summary,
        'evidence': 'Read-only local preflight and cached explicitly approved SSH discovery; not a live install assessment',
        'source_state': state if state in ('success', 'error', 'stale') else 'not_tested',
        'status_access': status_access if status_access in ('readable', 'permission_required', 'status_unavailable') else 'unverified',
        'service_verified': bool(isinstance(vpn_service, str) and vpn_service.strip()),
        'tunnel_verified': bool(isinstance(interface, str) and interface.strip()),
        'potential_impact': impact,
        'maintenance_window_review': maintenance_window,
        'administrator_approval_required': True,
        'remote_execution_enabled': False,
        'blockers': blockers,
        'actions': actions,
    }

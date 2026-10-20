"""Planner cases require no SSH, database or network access."""
import unittest
from backend.onboarding_planner import build_setup_plan


class SetupPlannerTests(unittest.TestCase):
    def entry(self, phase='eligible_for_read_only_discovery', discovery=None):
        checks = {
            'inventory_identity_complete': True,
            'monitoring_profile_approved': True,
            'local_configuration_ready': True,
        }
        if phase == 'inventory_incomplete':
            checks['inventory_identity_complete'] = False
        if phase == 'approval_required':
            checks['monitoring_profile_approved'] = False
        if phase == 'configuration_attention':
            checks['local_configuration_ready'] = False
        return {'phase': phase, 'checks': checks, 'discovery': discovery}

    def discover(self, *, access='readable', service='openvpn-server@server', state='success'):
        return {'state': state, 'checked_at_utc': '2026-10-13T00:00:00+00:00',
                'observation': {'vpn_service': service, 'vpn_interface': 'tun0', 'status_access': access}}

    def assert_safe(self, result):
        self.assertIs(result['remote_execution_enabled'], False)
        self.assertIs(result['administrator_approval_required'], True)
        self.assertTrue(result['actions'])
        self.assertNotIn('ssh_key_path', repr(result))
        self.assertNotIn('SUPPLIED_SECRET_VALUE', repr(result))

    def test_unapproved_never_plans_remote_change(self):
        plan = build_setup_plan(self.entry(phase='approval_required', discovery=self.discover()))
        self.assertEqual(plan['status'], 'blocked')
        self.assertEqual(plan['template'], 'access_approval')
        self.assert_safe(plan)

    def test_missing_inventory(self):
        plan = build_setup_plan(self.entry(phase='inventory_incomplete'))
        self.assertEqual(plan['template'], 'inventory')
        self.assert_safe(plan)

    def test_local_profile_mismatch(self):
        plan = build_setup_plan(self.entry(phase='configuration_attention'))
        self.assertEqual(plan['status'], 'blocked')
        self.assert_safe(plan)

    def test_no_snapshot_does_not_assume_fresh_vps(self):
        plan = build_setup_plan(self.entry())
        self.assertEqual(plan['template'], 'awaiting_discovery')
        self.assertNotIn('fresh VPS', plan['title'])
        self.assert_safe(plan)

    def test_stale_does_not_grant_readiness(self):
        plan = build_setup_plan(self.entry(discovery=self.discover(state='stale')))
        self.assertEqual(plan['status'], 'needs_discovery')
        self.assertEqual(plan['source_state'], 'stale')
        self.assert_safe(plan)

    def test_failed_probe_not_vpn_outage(self):
        plan = build_setup_plan(self.entry(discovery=self.discover(state='error')))
        self.assertEqual(plan['template'], 'ssh_connectivity')
        self.assertIn('Do not assume', plan['summary'])
        self.assert_safe(plan)

    def test_readable_status_file_requires_real_health_verification(self):
        plan = build_setup_plan(self.entry(discovery=self.discover()))
        self.assertEqual(plan['status'], 'monitoring_prepared')
        self.assertEqual(plan['status_access'], 'readable')
        self.assertFalse(plan['maintenance_window_review'])
        self.assert_safe(plan)

    def test_permissions_need_review_not_chmod_777(self):
        plan = build_setup_plan(self.entry(discovery=self.discover(access='permission_required')))
        self.assertEqual(plan['template'], 'status_permissions')
        self.assertTrue(plan['maintenance_window_review'])
        self.assertIn('chmod 777', plan['actions'][1]['guidance'])
        self.assert_safe(plan)

    def test_missing_service_not_classified_as_fresh(self):
        plan = build_setup_plan(self.entry(discovery=self.discover(service=None)))
        self.assertEqual(plan['template'], 'service_not_detected')
        self.assertIn('does not prove', plan['summary'])
        self.assert_safe(plan)

    def test_unknown_status_not_zero(self):
        plan = build_setup_plan(self.entry(discovery=self.discover(access='unknown')))
        self.assertEqual(plan['template'], 'status_unknown')
        self.assertEqual(plan['status_access'], 'unverified')
        self.assert_safe(plan)

    def test_no_raw_remote_secret_leak(self):
        discovery = self.discover(access='permission_required')
        discovery['observation']['warnings'] = ['SECRET_CANARY_83477']
        discovery['observation']['sensitive_path'] = '/home/test/.ssh/privatekey'
        plan = build_setup_plan(self.entry(discovery=discovery))
        self.assertNotIn('SECRET_CANARY_83477', repr(plan))
        self.assertNotIn('/home/test', repr(plan))
        self.assert_safe(plan)

    def test_discovery_never_overrides_missing_approval(self):
        plan = build_setup_plan(self.entry(phase='approval_required', discovery=self.discover()))
        self.assertEqual(plan['status'], 'blocked')
        self.assert_safe(plan)

    def test_admin_scan_modern_status_precedes_legacy_discovery(self):
        data = self.entry()
        data['checks']['monitoring_profile_approved'] = False
        data['checks']['admin_credential_ready'] = True
        data['onboarding_scan'] = {'state': 'success', 'classification': 'needs_review',
                                   'next_step': 'Package and service state needs confirmation.'}
        plan = build_setup_plan(data)
        self.assertEqual(plan['template'], 'verified_ssh_scan')
        self.assertEqual(plan['status'], 'review_required')
        self.assertNotIn('SSH enrollment', plan['title'])
        self.assertFalse(plan['remote_execution_enabled'])
        self.assert_safe(plan)

    def test_fresh_candidate_is_not_install_permission(self):
        data = self.entry()
        data['checks']['monitoring_profile_approved'] = False
        data['checks']['admin_credential_ready'] = True
        data['onboarding_scan'] = {'state': 'success', 'classification': 'fresh_candidate',
                                   'next_step': 'Confirm there are no other workloads.'}
        plan = build_setup_plan(data)
        self.assertEqual(plan['template'], 'verified_ssh_scan')
        self.assertTrue(plan['maintenance_window_review'])
        self.assertIn('candidate', plan['title'].lower())
        self.assertFalse(plan['remote_execution_enabled'])
        self.assert_safe(plan)

    def test_each_entry_is_independent(self):
        a = build_setup_plan(self.entry(discovery=self.discover(access='readable')))
        b = build_setup_plan(self.entry(discovery=self.discover(access='permission_required')))
        self.assertNotEqual(a['template'], b['template'])
        self.assert_safe(a)
        self.assert_safe(b)


if __name__ == '__main__':
    unittest.main()

import unittest
from backend.onboarding_preflight import describe_onboarding


def sample(**changes):
    kwargs = dict(server_id='id-1', server_name='Demo', client='Client A', host='192.0.2.10',
                  ssh_username='monitor', ssh_port=22, monitoring_configured=False,
                  monitoring_enabled=False, local_configuration_ready=False,
                  missing_settings=['monitoring profile has not been approved'])
    kwargs.update(changes)
    return describe_onboarding(**kwargs)


class OnboardingPreflightTests(unittest.TestCase):
    def test_unapproved_server_cannot_be_auto_contacted(self):
        result = sample()
        self.assertEqual(result['phase'], 'approval_required')
        self.assertFalse(result['remote_changes_allowed'])
        self.assertFalse(result['checks']['remote_ssh_test_performed'])
        self.assertNotIn('key_path', str(result))

    def test_blank_username_requires_inventory_update(self):
        self.assertEqual(sample(ssh_username=None)['phase'], 'inventory_incomplete')

    def test_approved_but_mismatched_profile_requires_attention(self):
        result = sample(monitoring_configured=True, monitoring_enabled=True,
                        local_configuration_ready=False, missing_settings=['private key path D:\\do-not-leak'])
        self.assertEqual(result['phase'], 'configuration_attention')
        self.assertNotIn('D:\\do-not-leak', str(result))

    def test_approved_ready_still_does_not_run_ssh(self):
        result = sample(monitoring_configured=True, monitoring_enabled=True,
                        local_configuration_ready=True, missing_settings=[])
        self.assertEqual(result['phase'], 'eligible_for_read_only_discovery')
        self.assertFalse(result['checks']['remote_openvpn_discovery_performed'])
        self.assertTrue(result['administrative_approval_required'])

    def test_encrypted_admin_credential_unblocks_scan_without_monitoring_profile(self):
        result = sample(admin_profile_ready=True, admin_profile_present=True)
        self.assertEqual(result['phase'], 'eligible_for_read_only_discovery')
        self.assertTrue(result['checks']['admin_credential_ready'])
        self.assertFalse(result['checks']['monitoring_profile_approved'])
        self.assertFalse(result['administrative_approval_required'])
        self.assertFalse(result['remote_changes_allowed'])
        self.assertFalse(result['checks']['remote_ssh_test_performed'])

    def test_admin_credential_enrollment_does_not_imply_live_ssh(self):
        result = sample(admin_profile_present=True, admin_profile_ready=False)
        self.assertEqual(result['phase'], 'approval_required')
        self.assertFalse(result['checks']['admin_credential_ready'])
        self.assertFalse(result['checks']['remote_openvpn_discovery_performed'])

    def test_many_clients_are_independent(self):
        a = sample(server_id='1', client='A')
        b = sample(server_id='2', client='B', ssh_username=None)
        self.assertEqual(a['phase'], 'approval_required')
        self.assertEqual(b['phase'], 'inventory_incomplete')


if __name__ == '__main__':
    unittest.main()

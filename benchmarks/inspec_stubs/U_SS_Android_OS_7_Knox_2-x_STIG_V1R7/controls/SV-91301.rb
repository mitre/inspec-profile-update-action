control 'SV-91301' do
  title 'If a third-party VPN client is installed in the personal space/container, it must not be configured with a DoD network (work) VPN profile.'
  desc 'The device VPN must be configured to disable access from the personal space/container since it is considered an untrusted environment. Therefore, apps located in the personal container on the device should not have the ability to access a DoD network. In addition, Smartphones do not generally meet security requirements for computer devices to connect directly to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if any third-party VPN client installed in the personal space/container on the device has been configured with a DoD network (work) VPN profile. 

This validation procedure is performed on the Samsung Android 7 with Knox device only.

On the Samsung Android 7 with Knox device, do the following:
1. Open the device settings.
2. Select "Apps".
3. Review the list of apps and if there are any VPN client apps installed open each one in turn. Review the list of VPN profiles configured on the VPN client.
4. Verify there are no DoD network VPN profiles configured on the VPN client.

If any third-party VPN client installed in the personal space/container has a DoD network VPN profile configured on the client, this is a finding.

Note: This setting cannot be managed by the MDM administrator and is a User Based Enforcement (UBE) requirement (unless an application white list/black list is configured for the personal space/container).'
  desc 'fix', 'If a third-party VPN client is installed in the personal space/container on a Samsung Android 7 with Knox device, do not configure the VPN client with a DoD network VPN profile.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76275r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76605'
  tag rid: 'SV-91301r1_rule'
  tag stig_id: 'KNOX-07-017130'
  tag gtitle: 'PP-MDF-301060'
  tag fix_id: 'F-83299r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

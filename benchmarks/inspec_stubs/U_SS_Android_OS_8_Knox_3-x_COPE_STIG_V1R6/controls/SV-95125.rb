control 'SV-95125' do
  title 'If a third-party VPN client is installed in the personal space, it must not be configured with a DoD network (work) VPN profile.'
  desc 'The device VPN must be configured to disable access from the personal space since it is considered an untrusted environment. Therefore, apps located in the personal space on the device should not have the ability to access a DoD network. In addition, smartphones do not generally meet security requirements for computer devices to connect directly to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if any third-party VPN client installed in the personal space/CONTAINER on the device has been configured with a DoD network (work) VPN profile. 

This validation procedure is performed on the Samsung Android 8 with Knox device only.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Apps".
3. Review the list of apps and if there are any VPN client apps installed, open each one in turn. Review the list of VPN profiles configured on the VPN client.
4. Verify there are no DoD network VPN profiles configured on the VPN client.

If any third-party VPN client installed in the personal space has a DoD network VPN profile configured on the client, this is a finding.

Note: This setting cannot be managed by the MDM Administrator and is a User Based Enforcement (UBE) requirement (unless an application whitelist/blacklist is configured for the personal space/CONTAINER).'
  desc 'fix', 'If a third-party VPN client is installed in the personal space on a Samsung Android 8 with Knox device, do not configure the VPN client with a DoD network VPN profile.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80093r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80421'
  tag rid: 'SV-95125r1_rule'
  tag stig_id: 'KNOX-08-023300'
  tag gtitle: 'PP-MDF-301060'
  tag fix_id: 'F-87227r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

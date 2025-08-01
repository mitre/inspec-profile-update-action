control 'SV-91295' do
  title 'The Samsung Android 7 with Knox VPN client must be configured in one of the following configurations: 1. Disabled 2. Configured for container use only. 3. Configured for per app use for the personal side.'
  desc 'The device VPN must be configured to disable access from the personal space/container since it is considered an untrusted environment. Therefore, apps located in the personal container on the device should not have the ability to access a DoD network. In addition, Smartphones do not generally meet security requirements for computer devices to connect directly to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'Not Applicable for the COBO use case.

The native VPN client on Samsung Android 7 with Knox must be configured in one of the following configurations:
1. Disabled
2. Configured for container use only
3. Configured for per app use for the personal side

This validation procedure covers the first of these options. This procedure is Not Applicable if option 2 or 3 was implemented at the site.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device native VPN client is disabled.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow VPN" checkbox in the "Android Restrictions" rule. 
2. Verify the checkbox is not selected.

On the Samsung Android 7 with Knox device, do the following:
1. Open device settings.
2. Select "Connections".
3. Select "More".
4. Verify the "VPN" is disabled (grayed out) and cannot be selected.

If the MDM console "Allow VPN" checkbox is selected or on the Samsung Android 7 with Knox device, the user can select "VPN", this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox native VPN client in one of the following configurations so that the device VPN is not available in the personal space:
1. Disabled
2. Configured for container use only.
3. Configured for per app use for the personal side.

This implementation guidance covers the first of these options.

On the MDM console, deselect the "Allow VPN" checkbox in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76267r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76599'
  tag rid: 'SV-91295r1_rule'
  tag stig_id: 'KNOX-07-017100'
  tag gtitle: 'PP-MDF-301060'
  tag fix_id: 'F-83293r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

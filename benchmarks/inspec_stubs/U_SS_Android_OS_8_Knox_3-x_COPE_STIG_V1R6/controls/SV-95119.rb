control 'SV-95119' do
  title 'The Samsung Android 8 with Knox VPN client must be configured in one of the following configurations:

1. Disabled;
2. Configured for CONTAINER use only; or
3. Configured for per app use for the personal side.'
  desc 'The device VPN must be configured to disable access from the personal space/CONTAINER since it is considered an untrusted environment. Therefore, apps located in the personal CONTAINER on the device should not have the ability to access a DoD network. In addition, smartphones do not generally meet security requirements for computer devices to connect directly to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'The native VPN client on Samsung Knox for Android must be configured in one of the following configurations: 
1. Disabled; 
2. Configured for CONTAINER use only; or 
3. Configured for per app use for the personal side.

This validation procedure covers the first of these options. This procedure is Not Applicable if option 2 or 3 was implemented at the site.

Review Samsung Android 8 with Knox configuration settings to determine if the mobile device native VPN client is disabled.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow VPN" check box in the "Android Restrictions" rule. 
2. Verify the check box is not selected.

On the Samsung Android 8 with Knox device, do the following:
1. Open device settings.
2. Select "Connections".
3. Select "More connection settings".
4. Verify the "VPN" is disabled (grayed out) and cannot be selected.

If the MDM console "Allow VPN" check box is selected or on the Samsung Android 8 with Knox device, the user can select "VPN", this is a finding.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox native VPN client in one of the following configurations so the device VPN is not available in the personal space:
1. Disabled; 
2. Configured for CONTAINER use only; or 
3. Configured for per app use for the personal side.

This implementation guidance covers the first of these options.

On the MDM console, deselect the "Allow VPN" check box in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80087r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80415'
  tag rid: 'SV-95119r1_rule'
  tag stig_id: 'KNOX-08-023000'
  tag gtitle: 'PP-MDF-301060'
  tag fix_id: 'F-87221r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

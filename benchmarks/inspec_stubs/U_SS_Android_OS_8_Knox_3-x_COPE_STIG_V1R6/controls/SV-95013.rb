control 'SV-95013' do
  title 'Samsung Android 8 with Knox must implement the management setting: Disable sharing of notification details outside the CONTAINER when the CONTAINER is locked.'
  desc 'Application notifications can include DoD sensitive data. If made available outside the CONTAINER, this information will be accessible to personal applications, resulting in potential compromise of DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing disabled sharing of notification details outside the CONTAINER when the CONTAINER is locked.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow Show detailed notifications" setting in the "Android Knox CONTAINER >> CONTAINER Restrictions" rule. 
2. Verify the setting is disabled.

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Select "Workspace Settings".
3. Select "Notifications and data".
4. Verify "Show notification content" is disabled and attempt to enable this setting.

If the MDM console "Allow Show detailed notifications" is not set to disabled or on the Samsung Android 8 with Knox device, the user is able to enable this setting, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce disabled sharing of notification details outside the CONTAINER when the CONTAINER is locked.

On the MDM console, disable the "Allow Show detailed notifications" setting in the "Android Knox CONTAINER >> CONTAINER Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80309'
  tag rid: 'SV-95013r1_rule'
  tag stig_id: 'KNOX-08-007500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87115r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

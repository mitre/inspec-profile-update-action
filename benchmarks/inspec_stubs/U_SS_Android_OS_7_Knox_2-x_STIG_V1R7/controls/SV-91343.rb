control 'SV-91343' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Disable sharing of notification details outside the Container when the container is locked.'
  desc 'Application notifications can include DoD sensitive data. If made available outside the container, this information will be accessible to personal applications, resulting in potential compromise of DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is enforcing disabled sharing of notification details outside the Container when the container is locked.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow Show detailed notifications" setting in the "Android Knox Container >> Container Restrictions" rule. 
2. Verify the setting is disabled.

On the Samsung Android 7 with Knox device, do the following:
1. Open the Knox container.
2. Select "Knox Settings".
3. Select "Notifications".
4. Verify "Hide content on lock screen" is disabled and attempt to enable this setting.

If the MDM console "Allow Show detailed notifications" is not set to disabled or on the Samsung Android 7 with Knox device, the user is able to enable this setting, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enforce disabled sharing of notification details outside the Container when the container is locked.

On the MDM console, disable the "Allow Show detailed notifications" setting in the "Android Knox Container >> Container Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76317r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76647'
  tag rid: 'SV-91343r1_rule'
  tag stig_id: 'KNOX-07-913600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83341r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

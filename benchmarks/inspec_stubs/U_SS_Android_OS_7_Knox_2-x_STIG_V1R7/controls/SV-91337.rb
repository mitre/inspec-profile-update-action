control 'SV-91337' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Disable sharing of calendar information outside the Container.'
  desc 'Calendar events can include potentially DoD-sensitive data such as names, contacts, dates and times, and locations. If made available outside the container, this information will be accessible to personal applications, resulting in potential compromise of DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is enforcing disabled sharing of calendar information outside the Container.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow calendar info outside container" setting in the "Android Knox Container >> Container Restrictions" rule. 
2. Verify the setting is disabled.

On the Samsung Android 7 with Knox device, do the following:
1. Open the Knox container.
2. Select "Knox Settings".
3. Select "Share contacts and calendars".
4. Verify "Export to Personal Mode – Calendar (from Knox)" (on some devices, shown as "Export to Personal Mode - S Planner") is disabled and attempt to enable this setting.

If the MDM console "Allow calendar info outside container" is not set to disabled or on the Samsung Android 7 with Knox device, the user is able to enable this setting, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enforce disabled sharing of calendar information outside the Container.

On the MDM console, disable the "Allow calendar info outside container" setting in the "Android Knox Container >> Container Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76311r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76641'
  tag rid: 'SV-91337r1_rule'
  tag stig_id: 'KNOX-07-913300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83335r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

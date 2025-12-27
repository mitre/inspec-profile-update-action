control 'SV-95111' do
  title 'Samsung Android 8 with Knox must implement the management setting: Disable sharing of calendar information outside the CONTAINER.'
  desc 'Calendar events can include potentially DoD sensitive data such as names, contacts, dates and times, and locations. If made available outside the CONTAINER, this information will be accessible to personal applications, resulting in potential compromise of DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing disabled sharing of calendar information outside the CONTAINER.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow calendar info outside CONTAINER" setting in the "Android Knox CONTAINER >> CONTAINER Restrictions" rule. 
2. Verify the setting is disabled.

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Select "Workspace settings".
3. Select "Notifications and data".
4. Select "Contacts and Calendar".
5. Verify "Export to Personal Mode – Calendar (from Workspace)" (on some devices, shown as "Export to Personal Mode - S Planner") is disabled and attempt to enable this setting.

If the MDM console "Allow calendar info outside CONTAINER" is not set to disabled or on the Samsung Android 8 with Knox device, the user can enable this setting, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce disabled sharing of calendar information outside the CONTAINER.

On the MDM console, disable the "Allow calendar info outside CONTAINER" setting in the "Android Knox CONTAINER >> CONTAINER Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80079r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80407'
  tag rid: 'SV-95111r1_rule'
  tag stig_id: 'KNOX-08-022000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87213r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

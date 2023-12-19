control 'SV-95115' do
  title 'Samsung Android 8 with Knox must be configured to disable sharing of contact information outside the CONTAINER.'
  desc 'Contacts can include DoD sensitive data and personally identifiable information (PII) of DoD employees, including names, numbers, addresses, and email addresses. If made available outside the CONTAINER, this information will be accessible to personal applications, resulting in potential compromise of DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing the disabling of sharing of contact information outside the CONTAINER. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow contact info outside CONTAINER" setting in the "Android Knox CONTAINER >> CONTAINER Restrictions" rule. 
2. Verify the setting is disabled.

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Select "Workspace settings".
3. Select "Notifications and data".
4. Select "Contacts and Calendar".
5. Verify "Export to Personal Mode - Contacts (from Workspace)" is disabled and attempt to enable this setting.

If the MDM console "Allow contact info outside CONTAINER" is not set to disabled or on the Samsung Android 8 with Knox device, the user is able to enable this setting, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce the disabling of sharing of contact information outside the CONTAINER.

On the MDM console, disable the "Allow contact info outside CONTAINER" setting in the "Android Knox CONTAINER >> CONTAINER Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80083r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80411'
  tag rid: 'SV-95115r1_rule'
  tag stig_id: 'KNOX-08-022400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87217r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-91341' do
  title 'The Samsung Android 7 with Knox must be configured to disable sharing of contact information outside the Container.'
  desc 'Contacts can include DoD-sensitive data and personally identifiable information (PII) of DoD employees, including names, numbers, addresses, and email addresses. If made available outside the container, this information will be accessible to personal applications, resulting in potential compromise of DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is enforcing disabled sharing of contact information outside the Container. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow contact info outside container" setting in the "Android Knox Container >> Container Restrictions" rule. 
2. Verify the setting is disabled.

On the Samsung Android 7 with Knox device, do the following:
1. Open the Knox container.
2. Select "Knox Settings".
3. Select "Share contacts and calendars".
4. Verify "Export to Personal Mode - Contacts (from Knox)" is disabled and attempt to enable this setting.

If the MDM console "Allow contact info outside container" is not set to disabled or on the Samsung Android 7 with Knox device, the user is able to enable this setting, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enforce disabled sharing of contact information outside the Container.

On the MDM console, do the following:
disable the "Allow contact info outside container" setting in the "Android Knox Container >> Container Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76315r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76645'
  tag rid: 'SV-91341r1_rule'
  tag stig_id: 'KNOX-07-913500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83339r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-91321' do
  title 'The Samsung Android 7 with Knox must use a NIAP certified container for work data and applications.'
  desc 'When a DoD mobile device contains apps in the personal container that have not been vetted by the DoD for malware or risky behaviors, the personal container must be considered an untrusted environment. Therefore the data separation implementation between the personal data container and the work container must meet the requirements of Mobile Device Fundamentals Protection Profile (FDP_ACF_EXT.1.2) to insure sensitive DoD data in the work container is adequately separated.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Not Applicable for the COBO use case.

Not Applicable if the AO has not approved unmanaged personal container.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device has the Knox container enabled.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Android Knox Container" rule. 
2. Verify the existence of this rule.

On the Samsung Android 7 with Knox device, do the following:
Verify the existence of the Knox icon on the device home screen or application menu or the notification bar pull-down menu.

If the MDM console "Android Knox Container" rule is not found in the MDM agent rule list (MDM vendor-specific check), or on the Samsung Android 7 with Knox device, the Knox icon is not present, this is a finding.'
  desc 'fix', 'Deploy DoD Samsung mobile devices with the Knox container and implement the Knox container. (See requirement KNOX-07-012800.)

Note: Samsung Knox is currently the only container technology/application that is NIAP certified for Samsung mobile devices.'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76295r1_chk'
  tag severity: 'high'
  tag gid: 'V-76625'
  tag rid: 'SV-91321r1_rule'
  tag stig_id: 'KNOX-07-018900'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83319r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

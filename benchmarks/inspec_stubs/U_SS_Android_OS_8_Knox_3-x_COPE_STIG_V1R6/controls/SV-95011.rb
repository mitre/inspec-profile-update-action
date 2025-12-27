control 'SV-95011' do
  title 'Samsung Android 8 with Knox must use a NIAP-certified CONTAINER for work data and applications.'
  desc 'When a DoD mobile device contains apps in the personal CONTAINER that have not been vetted by the DoD for malware or risky behaviors, the personal CONTAINER must be considered an untrusted environment. Therefore, the data separation implementation between the personal data CONTAINER and the work CONTAINER must meet the requirements of Mobile Device Fundamentals Protection Profile (FDP_ACF_EXT.1.2) to ensure sensitive DoD data in the work CONTAINER is adequately separated.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has the Knox CONTAINER enabled.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Android Knox CONTAINER" rule. 
2. Verify the existence of this rule.

On the Samsung Android 8 with Knox device, do the following:
Verify the existence of the Knox icon on the device home screen or application menu or the notification bar pull-down menu.

If the MDM console "Android Knox CONTAINER" rule is not found in the MDM agent rule list (MDM vendor-specific check) or on the Samsung Android 8 with Knox device, the Knox icon is not present, this is a finding.'
  desc 'fix', 'Deploy DoD Samsung mobile devices with the Knox CONTAINER and implement the Knox CONTAINER. (See requirement KNOX-08-007000.) 

Note: Samsung Knox is currently the only CONTAINER technology/application that is NIAP certified for Samsung mobile devices.'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79979r1_chk'
  tag severity: 'high'
  tag gid: 'V-80307'
  tag rid: 'SV-95011r1_rule'
  tag stig_id: 'KNOX-08-007100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87113r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

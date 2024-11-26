control 'SV-95003' do
  title 'The Samsung Android 8 with Knox CONTAINER must be configured to: Disable Bixby Vision.'
  desc "Bixby Vision's image and text recognition capabilities use cloud-based processing. This may leak sensitive DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device CONTAINER is configured to disable Bixby Vision.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM CONTAINER console, do the following:
1. Ask the MDM Administrator to display the "Application disable list" setting in the "Android Application" rule. 
2. Verify the list contains all Bixby Vision-related packages.

On the Samsung Android 8 with Knox device CONTAINER, do the following:
1. Open the Samsung Camera application.
2. Press the Bixby Vision "eye" icon.
3. Verify Bixby does not start.

If the Samsung Android 8 with Knox device starts Bixby Vision when pressing the Bixby Vision "eye" icon, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox CONTAINER to disable Bixby Vision.

On the MDM CONTAINER console, add all packages associated with the Bixby Vision feature to the "Application disable list" setting in the "Android Applications" rule.

Note: Refer to the Supplemental document for additional information.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79971r1_chk'
  tag severity: 'low'
  tag gid: 'V-80299'
  tag rid: 'SV-95003r1_rule'
  tag stig_id: 'KNOX-08-003600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87105r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-95117' do
  title 'Samsung Android 8 with Knox must implement the management setting: Disable Move Applications to CONTAINER.'
  desc 'Applications determined to be acceptable for personal use outside the CONTAINER might not be acceptable for use within the CONTAINER. The Move Applications to CONTAINER feature allows users to install personal side applications into the CONTAINER, resulting in potential compromise of DoD data. Disabling this feature mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing not allowing move of applications to CONTAINER.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Move Applications to CONTAINER" setting in the "Android Knox CONTAINER >> CONTAINER Restrictions" rule. 
2. Verify the setting is disabled.

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Select "Workspace settings".
3. Verify "Install apps" cannot be selected. (Note: If the Knox CONTAINER is configured as a folder type, "Add apps" should be disabled in the overflow menu.)

If the MDM console "Move Applications to CONTAINER" is not set to "Disabled" or on the Samsung Android 8 with Knox device, the user is able to select "Install apps", this is a finding.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox to enforce not allowing move of applications to CONTAINER.

On the MDM console, disable the "Move Applications to CONTAINER" setting in the "Android Knox CONTAINER >> CONTAINER Application" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80085r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80413'
  tag rid: 'SV-95117r1_rule'
  tag stig_id: 'KNOX-08-022600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87219r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

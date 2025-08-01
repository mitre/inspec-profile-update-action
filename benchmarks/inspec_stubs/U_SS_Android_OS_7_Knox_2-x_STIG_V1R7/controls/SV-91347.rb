control 'SV-91347' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Disable Move Applications to Container.'
  desc 'Applications determined to be acceptable for personal use outside the container might not be acceptable for use within the container. The Move Applications to Container feature allows users to install personal side applications into the container, resulting in potential compromise of DoD data. Disabling this feature mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is enforcing not allowing move of applications to Container.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Move Applications to Container" setting in the "Android Knox Container >> Container Restrictions" rule. 
2. Verify the setting is disabled.

On the Samsung Android 7 with Knox device, do the following:
1. Open the Knox Container.
2. Select "Knox Settings".
3. Verify "Install applications" cannot be selected. (Note: If the Knox Container is configured as a folder type, a "+" icon should not be visible in the list of applications.)

If the MDM console "Move Applications to Container" is not set to disabled or on the Samsung Android 7 with Knox device, user is able to select "Install applications", this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enforce not allowing move of applications to Container.

On the MDM console, disable the "Move Applications to Container" setting in the "Android Knox Container >> Container Application" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76321r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76651'
  tag rid: 'SV-91347r1_rule'
  tag stig_id: 'KNOX-07-913800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83345r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

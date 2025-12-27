control 'SV-95109' do
  title 'Samsung Android 8 with Knox must implement the management setting: Disable Move Files from CONTAINER to Personal.'
  desc 'Allowing movement of files between the CONTAINER and personal side will result in both personal data and sensitive DoD data being placed in the same space. This can potentially result in DoD data being transmitted to unauthorized recipients via personal email accounts or social applications, or transmission of malicious files to DoD accounts. Disabling this feature mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing not allowing moving of files from CONTAINER to Personal.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Move Files from CONTAINER to Personal" setting in the "Android Knox CONTAINER >> CONTAINER Restrictions" rule. 
2. Verify the setting is disabled.

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Select "My Files" application.
3. Select a file by long pressing a selection.
4. Select "Settings".
5. Select "Move to Personal mode".
6. Verify this operation is blocked.

If the MDM console "Move Files from CONTAINER to Personal" is not set to disabled or on the Samsung Android 8 with Knox device, the user is able to successfully move the selected file to the personal space, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox to enforce not allowing move of files from CONTAINER to Personal.

On the MDM console, disable the "Move Files from CONTAINER to Personal" setting in the "Android Knox CONTAINER >> CONTAINER Application" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80077r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80405'
  tag rid: 'SV-95109r1_rule'
  tag stig_id: 'KNOX-08-021800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87211r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

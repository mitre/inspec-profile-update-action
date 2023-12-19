control 'SV-95079' do
  title 'The Samsung Android 8 with Knox CONTAINER must implement the management setting: Configure disable Share Via List.'
  desc 'The "Share Via List" feature allows the transfer of data between nearby Samsung devices via Android Beam, Wi-Fi Direct, Link Sharing, and Share to Device. If sharing were enabled, sensitive DoD data could be compromised.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox CONTAINER configuration settings to determine if the mobile device is enforcing disabling of "Share Via List".

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow Share Via List" check box in the "Android CONTAINER Restrictions" rule. 
2. Verify the check box is not selected.

On the Samsung Android 8 with Knox device CONTAINER, attempt to share via list.

If the MDM console "Allow Share Via List" is selected in the CONTAINER or on the Samsung Android 8 with Knox device, the user is able to successfully share via list in the CONTAINER, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce disabling "Share Via List".

On the MDM console, deselect the "Allow Share Via List" check box in the "Android CONTAINER Restrictions" rule. 

Note: Disabling "Share Via List" will also disable functionality such as "Gallery Sharing" and "Direct Sharing".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80047r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80375'
  tag rid: 'SV-95079r1_rule'
  tag stig_id: 'KNOX-08-015955'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87181r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

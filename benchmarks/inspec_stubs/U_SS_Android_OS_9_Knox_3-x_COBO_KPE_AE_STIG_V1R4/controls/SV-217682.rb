control 'SV-217682' do
  title 'Samsung Android must be configured to disallow the Share Via List feature.'
  desc 'The Share Via List feature allows the transfer of data between nearby Samsung devices via Android Beam, Wi-Fi Direct, Link Sharing, and Share to Device. If sharing were enabled, sensitive DoD data could be compromised.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that Share Via List is disallowed. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox restrictions" group, verify that "disallow share via list" is selected. 

On the Samsung Android device, in the device, attempt to share by long pressing a file and tapping "Share". 

If on the MDM console "disallow share via list" is not selected, or on the Samsung Android device the user is able to share, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disallow Share Via List. 

On the MDM console, for the device, in the "Knox restrictions" group, select "disallow share via list". 

Note: Disabling "share via list" will also disable functionality such as "Gallery Sharing" and "Direct Sharing".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18901r362075_chk'
  tag severity: 'medium'
  tag gid: 'V-217682'
  tag rid: 'SV-217682r388482_rule'
  tag stig_id: 'KNOX-09-000770'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18899r362076_fix'
  tag 'documentable'
  tag legacy: ['SV-102989', 'V-92901']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

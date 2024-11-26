control 'SV-241227' do
  title 'Samsung Android Work Environment must be configured to enforce that Share Via List is disabled.'
  desc 'The "Share Via List" feature allows the transfer of data between nearby Samsung devices via Android Beam, Wi-Fi Direct, Link Sharing, and Share to Device. If sharing were enabled, sensitive DoD data could be compromised.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if Share Via List is disallowed.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the Work Environment KPE restrictions section, verify that "Share Via List" is set to "Disallow".

On the Samsung Android device, attempt to share by long pressing a file in the Work Environment and tapping "Share".

If on the management tool "Share Via List" is not set to "Disallow", or on the Samsung Android device the user is able to share, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to disallow Share Via List.

On the management tool, in the Work Environment KPE restrictions section, set "Share Via List" to "Disallow".

Note: Disabling Share Via List will also disable functionality such as Gallery Sharing and Direct Sharing.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44503r680320_chk'
  tag severity: 'medium'
  tag gid: 'V-241227'
  tag rid: 'SV-241227r680322_rule'
  tag stig_id: 'KNOX-10-011400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-44462r680321_fix'
  tag 'documentable'
  tag legacy: ['SV-109087', 'V-99983']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

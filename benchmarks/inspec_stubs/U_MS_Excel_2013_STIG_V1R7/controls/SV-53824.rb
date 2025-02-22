control 'SV-53824' do
  title 'The opening of pre-release versions of file formats new to Excel 2013 through the Compatibility Pack for Office 2013 and Excel 2013 Converter must be blocked.'
  desc 'By default, users are prompted to update automatic links.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Office 2013 Converters -> "Block opening of pre-release versions of file formats new to Excel 2013 through the Compatibility Pack for Office 2013 and Excel 2013 Converter" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\15.0\\excel\\security\\fileblock 

Criteria: If the value excel12betafilesfromconverters is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Office 2013 Converters -> "Block opening of pre-release versions of file formats new to Excel 2013 through the Compatibility Pack for Office 2013 and Excel 2013 Converter" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47889r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17322'
  tag rid: 'SV-53824r1_rule'
  tag stig_id: 'DTOO210'
  tag gtitle: 'DTOO210 - Block opening of pre-release versions'
  tag fix_id: 'F-46733r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

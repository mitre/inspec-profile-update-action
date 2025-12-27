control 'SV-33448' do
  title 'Pre-release versions of file formats new to Office Products must be blocked.'
  desc 'The Microsoft Office Compatibility Pack for Excel 2010 File Formats installed can open Office Open XML files saved with pre-release versions of Excel 2010. Excel Open XML files usually have the following extensions: .xlsx, .xlsm, .xltx, .xltm, .xlam.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Office 2010 Converters “Block opening of pre-release versions of file formats new to Excel 2010 through the Compatibility Pack for Office 2010 and Excel 2010 Converter” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\security\\fileblock

Criteria: If the value Excel12BetaFilesFromConverters is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Office 2010 Converters “Block opening of pre-release versions of file formats new to Excel 2010 through the Compatibility Pack for Office 2010 and Excel 2010 Converter” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-33931r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17322'
  tag rid: 'SV-33448r1_rule'
  tag stig_id: 'DTOO210 - Excel'
  tag gtitle: 'DTOO210 - Block opening of pre-release versions'
  tag fix_id: 'F-29620r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

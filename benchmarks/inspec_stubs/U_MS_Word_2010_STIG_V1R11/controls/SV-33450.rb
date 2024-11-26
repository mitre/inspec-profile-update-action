control 'SV-33450' do
  title 'Pre-release versions of file formats new to Office Products must be blocked.'
  desc 'This policy setting controls whether users with the Microsoft Office Compatibility Pack for Word 2010 File Formats installed can open Office Open XML files saved with pre-release versions of Word 2010. Word Open XML files usually have the following extensions: .docx, .docm, .dotx, .dotm, .xml.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Office 2010 Converters “Block opening of pre-release versions of file formats new to Word 2010 through the Compatibility Pack for Office 2010 and Word 2010 Open XML/Word 97-2003 Format Converter” must be set to “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\word\\security\\fileblock

Criteria: If the value Word12BetaFilesFromConverters is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Office 2010 Converters “Block opening of pre-release versions of file formats new to Word 2010 through the Compatibility Pack for Office 2010 and Word 2010 Open XML/Word 97-2003 Format Converter” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2010'
  tag check_id: 'C-33933r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17322'
  tag rid: 'SV-33450r1_rule'
  tag stig_id: 'DTOO210 - Word'
  tag gtitle: 'DTOO210 - Block opening of pre-release versions'
  tag fix_id: 'F-29622r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

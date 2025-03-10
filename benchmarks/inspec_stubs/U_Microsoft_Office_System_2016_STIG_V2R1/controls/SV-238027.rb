control 'SV-238027' do
  title 'Document metadata for password protected files must be protected.'
  desc "This policy setting determines whether metadata is encrypted when an Office Open XML file is password protected. If you enable this policy setting, Excel 2016, PowerPoint 2016, and Word 2016 encrypt metadata stored in password-protected Office Open XML files and override any configuration changes on users' computers. If you disable this policy setting, Office 2016 applications cannot encrypt metadata in password-protected Office Open XML files, which can reduce security. If you do not configure this policy setting, when an Office Open XML document is protected with a password and saved, any metadata associated with the document is encrypted along with the rest of the document's contents. If this configuration is changed, potentially sensitive information such as the document author and hyperlink references could be exposed to unauthorized people."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Protect document metadata for password protected files" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\security

Criteria: If the value OpenXMLEncryptProperty is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Protect document metadata for password protected files" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41237r650646_chk'
  tag severity: 'medium'
  tag gid: 'V-238027'
  tag rid: 'SV-238027r650648_rule'
  tag stig_id: 'DTOO188'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-41196r650647_fix'
  tag 'documentable'
  tag legacy: ['SV-85487', 'V-70863']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

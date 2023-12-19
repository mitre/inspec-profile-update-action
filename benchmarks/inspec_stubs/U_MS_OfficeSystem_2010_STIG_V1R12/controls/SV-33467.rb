control 'SV-33467' do
  title 'Document metadata for password protected files must be protected.'
  desc "When an Office Open XML document is protected with a password and saved, any metadata associated with the document is encrypted along with the rest of the document's contents. If this configuration is changed, potentially sensitive information such as the document author and hyperlink references could be exposed to unauthorized people."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings “Protect document metadata for password protected files” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\security

Criteria: If the value OpenXMLEncryptProperty is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings “Protect document metadata for password protected files” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33950r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17768'
  tag rid: 'SV-33467r1_rule'
  tag stig_id: 'DTOO188 - Office System'
  tag gtitle: 'DTOO188 - Protect document metadata'
  tag fix_id: 'F-29639r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

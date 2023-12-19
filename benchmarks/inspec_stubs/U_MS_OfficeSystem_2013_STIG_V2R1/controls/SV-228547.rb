control 'SV-228547' do
  title 'Document metadata for password protected files must be protected.'
  desc "When an Office Open XML document is protected with a password and saved, any metadata associated with the document is encrypted along with the rest of the document's contents. If this configuration is changed, potentially sensitive information such as the document author and hyperlink references could be exposed to unauthorized people."
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "Protect document metadata for password protected files" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\security

If the value 'OpenXMLEncryptProperty' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings "Protect document metadata for password protected files" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30780r498919_chk'
  tag severity: 'medium'
  tag gid: 'V-228547'
  tag rid: 'SV-228547r508020_rule'
  tag stig_id: 'DTOO188'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-30765r498920_fix'
  tag 'documentable'
  tag legacy: ['V-17768', 'SV-52725']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

control 'SV-228560' do
  title 'Rights managed Office Open XML files must be protected.'
  desc 'When Information Rights Management (IRM) is used to restrict access to an Office Open XML document, any metadata associated with the document is not encrypted. This configuration could allow potentially sensitive information such as the document author and hyperlink references to be exposed to unauthorized individuals.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "Protect document metadata for rights managed Office Open XML Files" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\security

If the value 'DRMEncryptProperty' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings "Protect document metadata for rights managed Office Open XML Files" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30793r498958_chk'
  tag severity: 'medium'
  tag gid: 'V-228560'
  tag rid: 'SV-228560r508020_rule'
  tag stig_id: 'DTOO187'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-30778r498959_fix'
  tag 'documentable'
  tag legacy: ['V-17769', 'SV-52724']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end

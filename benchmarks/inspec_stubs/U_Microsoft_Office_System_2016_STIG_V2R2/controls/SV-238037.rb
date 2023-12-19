control 'SV-238037' do
  title 'Encrypt document properties must be configured for OLE documents.'
  desc 'This policy setting allows you configure if the document properties are encrypted.  This applies to OLE documents (Office 97-2003 compatible) if the application is configured for CAPI RC4. If you enable this policy setting, the document properties will be encrypted. If you disable or do not configure this policy setting, the document properties will not be encrypted.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Encrypt document properties" is set to "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\security

Criteria: If the value EncryptDocProps is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Encrypt document properties" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41247r650676_chk'
  tag severity: 'medium'
  tag gid: 'V-238037'
  tag rid: 'SV-238037r650678_rule'
  tag stig_id: 'DTOO321'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-41206r650677_fix'
  tag 'documentable'
  tag legacy: ['SV-85509', 'V-70885']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end

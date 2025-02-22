control 'SV-34089' do
  title 'Encrypt document properties must be configured for OLE documents.'
  desc 'This policy setting allows you configure if the document properties are encrypted.  This applies to OLE documents (Office 97-2003 compatible) if the application is configured for CAPI RC4.  Disabling this setting will prevent the encryption of document properties, which may expose sensitive data.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings “Encrypt document properties” must be set to “Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\security

Criteria: If the value EncryptDocProps is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings “Encrypt document properties” to “Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-34449r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26704'
  tag rid: 'SV-34089r1_rule'
  tag stig_id: 'DTOO321 - Office System'
  tag gtitle: 'DTOO321 - Encrypt document properties'
  tag fix_id: 'F-30018r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end

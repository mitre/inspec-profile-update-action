control 'SV-228561' do
  title 'Encrypt document properties must be configured for OLE documents.'
  desc "This policy setting allows a document's properties to be encrypted.  This applies to OLE documents (Office 97-2003 compatible) if the application is configured for CAPI RC4.  Disabling this setting will prevent the encryption of document properties, which may expose sensitive data."
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "Encrypt document properties" is set to "Enabled". 

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\security

Criteria: If the value 'EncryptDocProps' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings "Encrypt document properties" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30794r498961_chk'
  tag severity: 'medium'
  tag gid: 'V-228561'
  tag rid: 'SV-228561r508020_rule'
  tag stig_id: 'DTOO321'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-30779r498962_fix'
  tag 'documentable'
  tag legacy: ['V-26704', 'SV-52757']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end

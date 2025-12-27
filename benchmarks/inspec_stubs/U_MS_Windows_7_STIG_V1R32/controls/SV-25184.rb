control 'SV-25184' do
  title 'Turn off indexing of encrypted files.'
  desc 'This check verifies that encrypted files are not indexed.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Windows Search\\

Value Name:  AllowIndexingEncryptedStoresOrItems

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Search “Allow indexing of encrypted files” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-15399r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15711'
  tag rid: 'SV-25184r1_rule'
  tag gtitle: 'Search – Encrypted Files Indexing'
  tag fix_id: 'F-15603r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

control 'SV-48249' do
  title 'Indexing of encrypted files must be turned off.'
  desc 'Indexing of encrypted files may expose sensitive data.  This setting prevents encrypted files from being indexed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Windows Search\\

Value Name: AllowIndexingEncryptedStoresOrItems

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Search -> "Allow indexing of encrypted files" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44927r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15711'
  tag rid: 'SV-48249r2_rule'
  tag stig_id: 'WN08-CC-000107'
  tag gtitle: 'Search – Encrypted Files Indexing'
  tag fix_id: 'F-41384r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

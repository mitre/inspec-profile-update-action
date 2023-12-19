control 'SV-253409' do
  title 'Indexing of encrypted files must be turned off.'
  desc 'Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\

Value Name: AllowIndexingEncryptedStoresOrItems

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Search >> "Allow indexing of encrypted files" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56862r829309_chk'
  tag severity: 'medium'
  tag gid: 'V-253409'
  tag rid: 'SV-253409r829311_rule'
  tag stig_id: 'WN11-CC-000305'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56812r829310_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

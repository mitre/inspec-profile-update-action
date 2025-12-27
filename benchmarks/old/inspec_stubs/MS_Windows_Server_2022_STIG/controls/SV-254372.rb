control 'SV-254372' do
  title 'Windows Server 2022 must prevent Indexing of encrypted files.'
  desc 'Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\

Value Name: AllowIndexingEncryptedStoresOrItems

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Search >> Allow indexing of encrypted files to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57857r848930_chk'
  tag severity: 'medium'
  tag gid: 'V-254372'
  tag rid: 'SV-254372r848932_rule'
  tag stig_id: 'WN22-CC-000410'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-57808r848931_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

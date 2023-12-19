control 'SV-88245' do
  title 'Indexing of encrypted files must be turned off.'
  desc 'Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\

Value Name: AllowIndexingEncryptedStoresOrItems

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Search >> "Allow indexing of encrypted files" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73663r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73581'
  tag rid: 'SV-88245r1_rule'
  tag stig_id: 'WN16-CC-000440'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-80031r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

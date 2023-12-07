control 'SV-29420' do
  title 'Search Companion prevented from automatically downloading content updates.'
  desc 'This check verifies that the system is configured to prevent Search Companion from automatically downloading content updates during local and Internet searches.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Policies\\Microsoft\\SearchCompanion 

Value Name: DisableContentFileUpdates 

Type: REG_DWORD 
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication setting ‘Turn off Search Companion content file updates’ to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32852r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14258'
  tag rid: 'SV-29420r1_rule'
  tag gtitle: 'Search Companion Content File Updates'
  tag fix_id: 'F-13583r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end

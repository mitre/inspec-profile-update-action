control 'SV-32364' do
  title 'Group Policy objects will be reprocessed even if they have not changed.'
  desc 'Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures that the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}

Value Name:  NoGPOListChanges

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy “Registry Policy Processing” to “Enabled” and select the option “Process even if the Group Policy objects have not changed”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32762r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4448'
  tag rid: 'SV-32364r1_rule'
  tag gtitle: 'Group Policy - Registry Policy Processing'
  tag fix_id: 'F-28955r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

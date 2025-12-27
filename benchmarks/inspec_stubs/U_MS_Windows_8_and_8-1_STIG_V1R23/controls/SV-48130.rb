control 'SV-48130' do
  title 'Group Policy objects must be reprocessed even if they have not changed.'
  desc 'Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures that the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}

Value Name: NoGPOListChanges

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy -> "Configure registry policy processing" to "Enabled" and select the option "Process even if the Group Policy objects have not changed".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44856r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4448'
  tag rid: 'SV-48130r2_rule'
  tag stig_id: 'WN08-CC-000028'
  tag gtitle: 'Group Policy - Registry Policy Processing'
  tag fix_id: 'F-41267r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

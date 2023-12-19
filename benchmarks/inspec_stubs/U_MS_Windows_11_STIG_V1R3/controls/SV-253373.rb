control 'SV-253373' do
  title 'Group Policy objects must be reprocessed even if they have not changed.'
  desc 'Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures that the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}

Value Name: NoGPOListChanges

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Group Policy >> "Configure registry policy processing" to "Enabled" and select the option "Process even if the Group Policy objects have not changed".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56826r829201_chk'
  tag severity: 'medium'
  tag gid: 'V-253373'
  tag rid: 'SV-253373r829203_rule'
  tag stig_id: 'WN11-CC-000090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56776r829202_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

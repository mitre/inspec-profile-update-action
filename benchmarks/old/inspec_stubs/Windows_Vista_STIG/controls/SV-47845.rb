control 'SV-47845' do
  title 'Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.'
  desc 'A compromised local administrator account can provide means for an attacker to move laterally between domain systems. 

With User Account Control enabled, filtering the privileged token for local administrator accounts will prevent the elevated privileges of these accounts from being used over the network.'
  desc 'fix', 'Configure the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System

Value Name:  LocalAccountTokenFilterPolicy

Type:  REG_DWORD
Value:  0'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-36439'
  tag rid: 'SV-47845r2_rule'
  tag stig_id: 'WINRG-000003'
  tag gtitle: 'Local admin accounts filtered token policy enabled on domain systems.'
  tag fix_id: 'F-40971r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end

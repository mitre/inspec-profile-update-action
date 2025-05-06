control 'SV-48238' do
  title 'The Windows Connect Now wizards must be disabled.'
  desc 'Windows Connect Now provides wizards for tasks such as "Set up a wireless router or access point" and must not be available to users.  Functions such as these may allow unauthorized connections to a system and the potential for sensitive information to be compromised.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\WCN\\UI\\

Value Name: DisableWcnUi

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now -> "Prohibit Access of the Windows Connect Now wizards" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44917r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15699'
  tag rid: 'SV-48238r2_rule'
  tag stig_id: 'WN08-CC-000013'
  tag gtitle: 'Network – Windows Connect Now Wizards'
  tag fix_id: 'F-41374r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

control 'SV-16588' do
  title 'Root Certificates Update'
  desc 'This check verifies that Root Certificates will not be updated automatically from the Microsoft site.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\

Value Name:  DisableRootAutoUpdate

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Automatic Root Certificates Update” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-15315r1_chk'
  tag severity: 'low'
  tag gid: 'V-15671'
  tag rid: 'SV-16588r1_rule'
  tag gtitle: 'Root Certificates Update'
  tag fix_id: 'F-15538r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end

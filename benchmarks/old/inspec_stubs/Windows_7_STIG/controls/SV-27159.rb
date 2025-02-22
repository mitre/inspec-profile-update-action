control 'SV-27159' do
  title 'The default autorun behavior must be configured to prevent autorun commands.'
  desc 'Allowing autorun commands to execute may introduce malicious code to a system.  Configuring this setting prevents autorun commands from executing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name:  NoAutorun

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Default behavior for AutoRun" to "Enabled" with "Do not execute any autorun commands" selected.'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-58019r1_chk'
  tag severity: 'high'
  tag gid: 'V-22692'
  tag rid: 'SV-27159r2_rule'
  tag gtitle: 'Default Autorun Behavior'
  tag fix_id: 'F-62381r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

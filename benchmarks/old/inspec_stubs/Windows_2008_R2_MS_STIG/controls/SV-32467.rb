control 'SV-32467' do
  title 'The default autorun behavior will be configured to prevent autorun commands.'
  desc 'Allowing autorun commands to execute may introduce malicious code to a system.  Configuring this setting prevents autorun commands from executing.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name:  NoAutorun

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> “Default behavior for AutoRun” to “Enabled:Do not execute any autorun commands”.'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-28096r1_chk'
  tag severity: 'high'
  tag gid: 'V-22692'
  tag rid: 'SV-32467r1_rule'
  tag gtitle: 'Default Autorun Behavior'
  tag fix_id: 'F-24430r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

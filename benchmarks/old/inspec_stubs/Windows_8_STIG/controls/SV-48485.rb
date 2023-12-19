control 'SV-48485' do
  title 'The default autorun behavior must be configured to prevent autorun commands.'
  desc 'Allowing autorun commands to execute may introduce malicious code to a system.  Configuring this setting prevents autorun commands from executing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoAutorun

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45144r2_chk'
  tag severity: 'high'
  tag gid: 'V-22692'
  tag rid: 'SV-48485r2_rule'
  tag stig_id: 'WN08-CC-000073'
  tag gtitle: 'Default Autorun Behavior'
  tag fix_id: 'F-41611r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

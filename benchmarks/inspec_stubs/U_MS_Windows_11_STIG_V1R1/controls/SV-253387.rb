control 'SV-253387' do
  title 'The default autorun behavior must be configured to prevent autorun commands.'
  desc 'Allowing autorun commands to execute may introduce malicious code to a system. Configuring this setting prevents autorun commands from executing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoAutorun

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56840r829243_chk'
  tag severity: 'high'
  tag gid: 'V-253387'
  tag rid: 'SV-253387r829245_rule'
  tag stig_id: 'WN11-CC-000185'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-56790r829244_fix'
  tag 'documentable'
  tag cci: ['CCI-001734']
  tag nist: ['CM-10 (1)']
end

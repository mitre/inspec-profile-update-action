control 'SV-226185' do
  title 'The default Autorun behavior must be configured to prevent Autorun commands.'
  desc 'Allowing Autorun commands to execute may introduce malicious code to a system.  Configuring this setting prevents Autorun commands from executing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoAutorun

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands".'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27887r475878_chk'
  tag severity: 'high'
  tag gid: 'V-226185'
  tag rid: 'SV-226185r569184_rule'
  tag stig_id: 'WN12-CC-000073'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-27875r475879_fix'
  tag 'documentable'
  tag legacy: ['SV-53124', 'V-22692']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

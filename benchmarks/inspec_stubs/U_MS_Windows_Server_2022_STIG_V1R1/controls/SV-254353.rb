control 'SV-254353' do
  title 'Windows Server 2022 default AutoRun behavior must be configured to prevent AutoRun commands.'
  desc 'Allowing AutoRun commands to execute may introduce malicious code to a system. Configuring this setting prevents AutoRun commands from executing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoAutorun

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> Set the default behavior for AutoRun to "Enabled" with "Do not execute any autorun commands" selected.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57838r848873_chk'
  tag severity: 'high'
  tag gid: 'V-254353'
  tag rid: 'SV-254353r848875_rule'
  tag stig_id: 'WN22-CC-000220'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-57789r848874_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

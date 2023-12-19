control 'SV-25295' do
  title 'Prevent access to Windows Online Troubleshooting Service (WOTS).'
  desc 'This setting prevents users from searching troubleshooting content on Microsoft servers.  Only local content will be available.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy\\

Value Name:  EnableQueryRemoteServer

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Scripted Diagnostics -> “Troubleshooting: Allow users to access online troubleshooting content on Microsoft servers from the Troubleshooting Control Panel (via Windows Online Troubleshooting Service - WOTS)” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26856r1_chk'
  tag severity: 'low'
  tag gid: 'V-21969'
  tag rid: 'SV-25295r1_rule'
  tag gtitle: 'Windows Online Troubleshooting Service'
  tag fix_id: 'F-22956r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

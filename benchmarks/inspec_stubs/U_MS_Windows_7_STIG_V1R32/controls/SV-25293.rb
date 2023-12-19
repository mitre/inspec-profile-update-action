control 'SV-25293' do
  title 'Prevent Microsoft Support Diagnostic Tool (MSDT) interactive communication with Microsoft.'
  desc 'This setting prevents the MSDT from communicating with and sending collected data to Microsoft, the default support provider.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy\\

Value Name:  DisableQueryRemoteServer

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Microsoft Support Diagnostic Tool -> “Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with Support Provider” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26855r1_chk'
  tag severity: 'low'
  tag gid: 'V-21967'
  tag rid: 'SV-25293r1_rule'
  tag gtitle: 'MSDT Interactive Communication'
  tag fix_id: 'F-22955r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

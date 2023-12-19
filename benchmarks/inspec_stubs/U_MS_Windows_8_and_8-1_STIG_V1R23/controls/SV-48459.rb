control 'SV-48459' do
  title 'Microsoft Support Diagnostic Tool (MSDT) interactive communication with Microsoft must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents the MSDT from communicating with and sending collected data to Microsoft, the default support provider.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy\\

Value Name: DisableQueryRemoteServer

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Microsoft Support Diagnostic Tool -> "Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with Support Provider" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45123r3_chk'
  tag severity: 'low'
  tag gid: 'V-21967'
  tag rid: 'SV-48459r2_rule'
  tag stig_id: 'WN08-CC-000066'
  tag gtitle: 'MSDT Interactive Communication'
  tag fix_id: 'F-41586r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

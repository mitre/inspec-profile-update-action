control 'SV-225359' do
  title 'Access to Windows Online Troubleshooting Service (WOTS) must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents users from searching troubleshooting content on Microsoft servers.  Only local content will be available.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy\\

Value Name: EnableQueryRemoteServer

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Scripted Diagnostics -> "Troubleshooting: Allow users to access online troubleshooting content on Microsoft servers from the Troubleshooting Control Panel (via the Windows Online Troubleshooting Service - WOTS)" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27058r471419_chk'
  tag severity: 'low'
  tag gid: 'V-225359'
  tag rid: 'SV-225359r569185_rule'
  tag stig_id: 'WN12-CC-000067'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27046r471420_fix'
  tag 'documentable'
  tag legacy: ['V-21969', 'SV-53188']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

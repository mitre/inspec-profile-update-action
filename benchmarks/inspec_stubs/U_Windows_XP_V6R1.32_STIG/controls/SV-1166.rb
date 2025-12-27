control 'SV-1166' do
  title 'The Windows SMB client is not enabled to perform SMB packet signing when possible.'
  desc 'If this policy is enabled, it causes the Windows Server Message Block (SMB) client to perform SMB packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Microsoft Network Client: Digitally sign communications (if server agrees)” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name:  EnableSecuritySignature

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Microsoft Network Client: Digitally sign communications (if server agrees)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-4361r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1166'
  tag rid: 'SV-1166r1_rule'
  tag gtitle: 'SMB Client Packet Signing (if server agrees)'
  tag fix_id: 'F-103r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end

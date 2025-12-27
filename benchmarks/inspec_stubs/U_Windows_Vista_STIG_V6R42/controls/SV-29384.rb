control 'SV-29384' do
  title 'The Windows Server SMB client is not enabled to always perform SMB packet signing.'
  desc 'If this policy is enabled, it causes the Windows Server Message Block (SMB) client to perform SMB packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Microsoft Network Client: Digitally sign communications (always)” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name:  RequireSecuritySignature

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Microsoft Network Client: Digitally sign communications (always)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-3110r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6832'
  tag rid: 'SV-29384r1_rule'
  tag gtitle: 'SMB Client Packet Signing (Always)'
  tag fix_id: 'F-6519r1_fix'
  tag 'documentable'
  tag potential_impacts: 'If the environment is a mixed one, with down-level OSs, or maintains trusts with down-level OSs, then this to the required setting could cause compatibility problems.'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end

control 'SV-48132' do
  title 'The Windows SMB client must be configured to always perform SMB packet signing.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations.  Digitally signed SMB packets aid in preventing man-in-the-middle attacks.  If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Microsoft Network Client: Digitally sign communications (always)" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name: RequireSecuritySignature

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft Network Client: Digitally sign communications (always)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44858r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6832'
  tag rid: 'SV-48132r1_rule'
  tag stig_id: 'WN08-SO-000028'
  tag gtitle: 'SMB Client Packet Signing (Always)'
  tag fix_id: 'F-41269r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end

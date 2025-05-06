control 'SV-48058' do
  title 'The Windows SMB client must be enabled to perform SMB packet signing when possible.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations.   If this policy is enabled, the SMB client will request packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Microsoft Network Client: Digitally sign communications (if server agrees)" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft Network Client: Digitally sign communications (if server agrees)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44797r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1166'
  tag rid: 'SV-48058r1_rule'
  tag stig_id: 'WN08-SO-000029'
  tag gtitle: 'SMB Client Packet Signing (if server agrees)'
  tag fix_id: 'F-41196r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end

control 'SV-48054' do
  title 'The Windows SMB server must perform SMB packet signing when possible.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations.   Digitally signed SMB packets aid in preventing man-in-the-middle attacks.  If this policy is enabled, the SMB server will negotiate SMB packet signing as requested by the client.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Microsoft Network Server: Digitally sign communications (if client agrees)" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft Network Server: Digitally sign communications (if Client agrees)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44793r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1162'
  tag rid: 'SV-48054r1_rule'
  tag stig_id: 'WN08-SO-000033'
  tag gtitle: 'SMB Server Packet Signing (if client agrees)'
  tag fix_id: 'F-41192r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end

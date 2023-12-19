control 'SV-48131' do
  title 'Outgoing secure channel traffic must be encrypted or signed.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted.  If this policy is enabled, outgoing secure channel traffic will be encrypted and signed.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Domain Member: Digitally encrypt or sign secure channel data (always)" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RequireSignOrSeal

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain Member: Digitally encrypt or sign secure channel data (always)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44857r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6831'
  tag rid: 'SV-48131r1_rule'
  tag stig_id: 'WN08-SO-000012'
  tag gtitle: 'Encrypting and Signing of Secure Channel Traffic'
  tag fix_id: 'F-41268r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end

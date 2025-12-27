control 'SV-25042' do
  title 'The maximum age for machine account passwords is not set to requirements.'
  desc 'This setting controls the maximum password age that a machine account may have.  This setting should be set to no more than 30 days, ensuring the machine changes its password monthly.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Domain Member: Maximum Machine Account Password Age” is 0 or greater than 30 (30 is the default), this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: MaximumPasswordAge

Value Type: REG_DWORD
Value: 30'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Domain Member: Maximum Machine Account Password Age” to 30 or less, but not 0.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-39126r1_chk'
  tag severity: 'low'
  tag gid: 'V-3373'
  tag rid: 'SV-25042r1_rule'
  tag gtitle: 'Maximum Machine Account Password Age'
  tag fix_id: 'F-34273r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

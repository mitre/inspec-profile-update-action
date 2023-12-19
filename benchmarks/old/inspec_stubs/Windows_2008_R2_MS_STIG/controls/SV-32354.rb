control 'SV-32354' do
  title 'The system will be configured to prevent IP source routing.'
  desc 'Protects against IP source routing spoofing.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)” is not set to “Highest protection, source routing is completely disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name:  DisableIPSourceRouting

Value Type:  REG_DWORD
Value:  2'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)” to “Highest protection, source routing is completely disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-282r1_chk'
  tag severity: 'low'
  tag gid: 'V-4110'
  tag rid: 'SV-32354r1_rule'
  tag gtitle: 'Disable IP Source Routing'
  tag fix_id: 'F-5713r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

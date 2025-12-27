control 'SV-32356' do
  title 'The system will be configured to disable the Internet Router Discover Protocol (IRDP).'
  desc 'Enables or disables the Internet Router Discovery Protocol (IRDP) used to detect and configure Default Gateway addresses on the computer.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)” is not set to “Disabled”, then this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: PerformRouterDiscovery

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-321r1_chk'
  tag severity: 'low'
  tag gid: 'V-4112'
  tag rid: 'SV-32356r1_rule'
  tag gtitle: 'Disable Router Discovery'
  tag fix_id: 'F-5730r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

control 'SV-29364' do
  title 'The system is configured to redirect ICMP.'
  desc 'When disabled, forces ICMP to be routed via shortest path first.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name:  EnableICMPRedirect

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-286r1_chk'
  tag severity: 'low'
  tag gid: 'V-4111'
  tag rid: 'SV-29364r1_rule'
  tag gtitle: 'Disable ICMP Redirect'
  tag fix_id: 'F-5715r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

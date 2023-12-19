control 'SV-48544' do
  title 'The system must be configured to disable the Internet Router Discovery Protocol (IRDP).'
  desc 'The Internet Router Discovery Protocol (IRDP) is used to detect and configure default gateway addresses on the computer.  If a router is impersonated on a network, traffic could be routed through the compromised system.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)" is not set to "Disabled", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \System\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: PerformRouterDiscovery

Value Type: REG_DWORD
Value: 0)
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44850r1_chk'
  tag severity: 'low'
  tag gid: 'V-4112'
  tag rid: 'SV-48544r1_rule'
  tag stig_id: 'WN08-SO-000044'
  tag gtitle: 'Disable Router Discovery'
  tag fix_id: 'F-41261r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

control 'SV-226308' do
  title 'The system must be configured to disable the Internet Router Discovery Protocol (IRDP).'
  desc 'The Internet Router Discovery Protocol (IRDP) is used to detect and configure default gateway addresses on the computer.  If a router is impersonated on a network, traffic could be routed through the compromised system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: PerformRouterDiscovery

Value Type: REG_DWORD
Value: 0'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)" to "Disabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28010r476768_chk'
  tag severity: 'low'
  tag gid: 'V-226308'
  tag rid: 'SV-226308r794563_rule'
  tag stig_id: 'WN12-SO-000044'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-27998r476769_fix'
  tag 'documentable'
  tag legacy: ['SV-52926', 'V-4112']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

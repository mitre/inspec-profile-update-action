control 'SV-254337' do
  title 'Windows Server 2022 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes.'
  desc 'Allowing ICMP redirect of routes can lead to traffic not being routed properly. When disabled, this forces ICMP to be routed via the shortest path first.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: EnableICMPRedirect

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes to "Disabled".

This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG package. "MSS-Legacy.admx" and "MSS-Legacy.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57822r848825_chk'
  tag severity: 'low'
  tag gid: 'V-254337'
  tag rid: 'SV-254337r848827_rule'
  tag stig_id: 'WN22-CC-000050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57773r848826_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

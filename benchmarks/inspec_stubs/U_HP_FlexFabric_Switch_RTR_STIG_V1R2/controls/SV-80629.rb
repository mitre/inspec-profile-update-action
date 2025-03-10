control 'SV-80629' do
  title 'The HP FlexFabric Switch must establish boundaries for IPv6 Admin-Local, IPv6 Site-Local, IPv6 Organization-Local scope, and IPv4 Local-Scope multicast traffic.'
  desc 'If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel.

Administrative scoped multicast addresses are locally assigned and are to be used exclusively by the enterprise network or enclave. Administrative scoped multicast traffic must not cross the enclave perimeter in either direction. Restricting multicast traffic makes it more difficult for a malicious user to access sensitive traffic.

Admin-Local scope is encouraged for any multicast traffic within a network intended for network management, as well as for control plane traffic that must reach beyond link-local destinations.'
  desc 'check', 'Review the multicast topology diagram to determine if there are any documented Admin-Local (FFx4::/16), Site-Local (FFx5::/16), or Organization-Local (FFx8::/16) multicast boundaries for IPv6 traffic or any Local-Scope (239.255.0.0/16) boundaries for IPv4 traffic.

Verify the appropriate boundaries are configured on the applicable multicast-enabled interfaces.

If appropriate multicast scope boundaries have not been configured, this is a finding.

[HP] display current-configuration interface GigabitEthernet 0/2
interface GigabitEthernet0/2
 port link-mode route
 description OVERSUBSCRIBE
 ip address 201.6.36.1 255.255.255.0
 multicast boundary 239.255.0.0 16
 ipv6 multicast boundary scope 4
 ipv6 multicast boundary scope 5
 ipv6 multicast boundary scope 8
 ipv6 address 2115:C:24::1/120'
  desc 'fix', 'Configure the appropriate boundaries to contain packets addressed within the administratively scoped zone. Defined multicast addresses are FFx4::/16, FFx5::/16, FFx8::/16, and 239.255.0.0/16.

Enable ip multicast globally
[HP] ipv6 multicast routing

Specify the IPv6 multicast boundary on multicast enabled interface

[HP] interface gig 0/2
[HP-GigabitEthernet0/2] ipv6 multicast boundary scope 4
[HP-GigabitEthernet0/2] ipv6 multicast boundary scope 5
[HP-GigabitEthernet0/2] ipv6 multicast boundary scope 8

specify the IPv4 multicast boundary on multicast enabled interfaces

[HP-GigabitEthernet0/2] multicast boundary 239.255.0.0 16'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66785r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66139'
  tag rid: 'SV-80629r1_rule'
  tag stig_id: 'HFFS-RT-000026'
  tag gtitle: 'SRG-NET-000019-RTR-000005'
  tag fix_id: 'F-72215r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

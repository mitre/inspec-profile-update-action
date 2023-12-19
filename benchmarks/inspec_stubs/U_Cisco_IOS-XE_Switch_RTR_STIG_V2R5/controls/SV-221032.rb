control 'SV-221032' do
  title 'The Cisco BGP switch must be configured to use its loopback address as the source address for iBGP peering sessions.'
  desc 'Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of the BGP switches. It is easier to construct appropriate ingress filters for switch management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the switch’s loopback address instead of the numerous physical interface addresses.

When the loopback address is used as the source for eBGP peering, the BGP session will be harder to hijack since the source address to be used is not known globally, making it more difficult for a hacker to spoof an eBGP neighbor. By using traceroute, a hacker can easily determine the addresses for an eBGP speaker when the IP address of an external interface is used as the source address. The switches within the iBGP domain should also use loopback addresses as the source address when establishing BGP sessions.'
  desc 'check', 'Step 1: Review the switch configuration to verify that a loopback address has been configured.

interface Loopback0
 ip address 10.1.1.1 255.255.255.255

Step 2: Verify that the loopback interface is used as the source address for all iBGP sessions.

router bgp xx
 no synchronization
 no bgp enforce-first-as
 bgp log-neighbor-changes
 redistribute static
 neighbor 10.1.1.1 remote-as xx
 neighbor 10.1.1.1 password xxxxxxxx
 neighbor 10.1.1.1 update-source Loopback0

If the switch does not use its loopback address as the source address for all iBGP sessions, this is a finding.'
  desc 'fix', 'Configure the switch to use its loopback address as the source address for all iBGP peering.

SW1(config)#router bgp xx
SW1(config-switch)#neighbor 10.1.1.1 update-source Loopback0'
  impact 0.3
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22747r408890_chk'
  tag severity: 'low'
  tag gid: 'V-221032'
  tag rid: 'SV-221032r622190_rule'
  tag stig_id: 'CISC-RT-000580'
  tag gtitle: 'SRG-NET-000512-RTR-000001'
  tag fix_id: 'F-22736r408891_fix'
  tag 'documentable'
  tag legacy: ['SV-110885', 'V-101781']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

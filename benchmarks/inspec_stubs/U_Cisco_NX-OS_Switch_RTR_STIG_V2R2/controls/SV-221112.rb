control 'SV-221112' do
  title 'The Cisco BGP switch must be configured to use its loopback address as the source address for iBGP peering sessions.'
  desc 'Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of the BGP switches. It is easier to construct appropriate ingress filters for switch management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the switch’s loopback address instead of the numerous physical interface addresses.

When the loopback address is used as the source for eBGP peering, the BGP session will be harder to hijack since the source address to be used is not known globally, making it more difficult for a hacker to spoof an eBGP neighbor. By using traceroute, a hacker can easily determine the addresses for an eBGP speaker when the IP address of an external interface is used as the source address. The switches within the iBGP domain should also use loopback addresses as the source address when establishing BGP sessions.'
  desc 'check', 'Step 1: Review the switch configuration to verify that a loopback address has been configured.

interface loopback0
 ip address 10.1.1.1/32

Step 2: Verify that the loopback interface is used as the source address for all iBGP sessions.

router bgp xx
 router-id 10.1.1.1
 address-family ipv4 unicast
 neighbor 10.1.12.2 remote-as xx
 password 3 7b07d1b3023056a9
 update-source loopback0 

If the switch does not use its loopback address as the source address for all iBGP sessions, this is a finding.'
  desc 'fix', 'Configure the switch to use its loopback address as the source address for all iBGP peering.

SW1(config)# router bgp xx
SW1(config-router)# neighbor 10.1.12.2 
SW1(config-router-neighbor)# update-source lo0
SW1(config-router-neighbor)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22827r409825_chk'
  tag severity: 'low'
  tag gid: 'V-221112'
  tag rid: 'SV-221112r622190_rule'
  tag stig_id: 'CISC-RT-000580'
  tag gtitle: 'SRG-NET-000512-RTR-000001'
  tag fix_id: 'F-22816r409826_fix'
  tag 'documentable'
  tag legacy: ['SV-111043', 'V-101939']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

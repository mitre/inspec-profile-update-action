control 'SV-216786' do
  title 'The Cisco BGP router must be configured to use its loopback address as the source address for iBGP peering sessions.'
  desc 'Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of the BGP routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router’s loopback address instead of the numerous physical interface addresses.

When the loopback address is used as the source for eBGP peering, the BGP session will be harder to hijack since the source address to be used is not known globally—making it more difficult for a hacker to spoof an eBGP neighbor. By using traceroute, a hacker can easily determine the addresses for an eBGP speaker when the IP address of an external interface is used as the source address. The routers within the iBGP domain should also use loopback addresses as the source address when establishing BGP sessions.'
  desc 'check', 'Step 1: Review the router configuration to verify that a loopback address has been configured.

interface Loopback0
 ip address 10.1.1.1 255.255.255.255

Step 2: Verify that the loopback interface is used as the source address for all iBGP sessions.

router bgp xx
 address-family ipv4 unicast
 !
 neighbor 10.1.23.3
  remote-as xx
  update-source Loopback0
  
If the router does not use its loopback address as the source address for all iBGP sessions, this is a finding.'
  desc 'fix', 'Configure the router to use its loopback address as the source address for all iBGP peering.

RP/0/0/CPU0:R2(config)#router bgp 2
RP/0/0/CPU0:R2(config-bgp)#neighbor 10.1.24.4
RP/0/0/CPU0:R2(config-bgp-nbr)#update-source lo0
RP/0/0/CPU0:R2(config-bgp-nbr)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18018r288735_chk'
  tag severity: 'low'
  tag gid: 'V-216786'
  tag rid: 'SV-216786r531087_rule'
  tag stig_id: 'CISC-RT-000580'
  tag gtitle: 'SRG-NET-000512-RTR-000001'
  tag fix_id: 'F-18016r288736_fix'
  tag 'documentable'
  tag legacy: ['SV-105917', 'V-96779']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

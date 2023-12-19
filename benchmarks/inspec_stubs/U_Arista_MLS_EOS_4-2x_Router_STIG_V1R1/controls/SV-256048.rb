control 'SV-256048' do
  title 'The Arista BGP router must be configured to use its loopback address as the source address for iBGP peering sessions.'
  desc "Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of the BGP routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router's loopback address instead of the numerous physical interface addresses.

When the loopback address is used as the source for eBGP peering, the BGP session will be harder to hijack since the source address to be used is not known globally—making it more difficult for a hacker to spoof an eBGP neighbor. By using traceroute, a hacker can easily determine the addresses for an eBGP speaker when the IP address of an external interface is used as the source address. The routers within the iBGP domain should also use loopback addresses as the source address when establishing BGP sessions."
  desc 'check', 'Review the Arista router configuration to verify a loopback address has been configured.

Verify a loopback interface is used as the source address for all iBGP sessions.

Step 1: To verify the Loopback interface is defined, execute the command "sh run int loopback YY".

interface loopback 0
  ip address 10.1.1.1/32

Step 2: To verify a loopback interface is used as the source address for all iBGP sessions, execute the command "sh run sec router bgp".

router bgp 65001
   router-id 10.1.1.1
   neighbor Peer_Leaf peer group
   neighbor Peer_Leaf remote-as 65001
   neighbor Peer_Leaf update-source Loopback0
   neighbor 10.2.2.2 peer group Peer_Leaf
   
If the Arista router does not use its loopback address as the source address for all iBGP sessions, this is a finding.'
  desc 'fix', "Ensure the Arista router's loopback address is used as the source address when originating traffic.

Step 1: Configure the Loopback interface.

LEAF-1A(config)#interface Loopback0
LEAF-1A(config-if-Lo0)#ip address 10.1.1.1/32

Step 2: Configure the loopback interface as source for all iBGP sessions.

router bgp 65001
LEAF-1A(config-router-bgp)#
LEAF-1A(config-router-bgp)#neighbor Peer_Leaf peer group
LEAF-1A(config-router-bgp)#Peer_Leaf remote-as 65001
LEAF-1A(config-router-bgp)#Peer_Leaf update-source Loopback0
LEAF-1A(config-router-bgp)#10.2.2.2 peer group Peer_Leaf"
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59724r882484_chk'
  tag severity: 'low'
  tag gid: 'V-256048'
  tag rid: 'SV-256048r882486_rule'
  tag stig_id: 'ARST-RT-000690'
  tag gtitle: 'SRG-NET-000512-RTR-000001'
  tag fix_id: 'F-59667r882485_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

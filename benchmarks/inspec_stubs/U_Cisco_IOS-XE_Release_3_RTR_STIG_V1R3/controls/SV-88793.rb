control 'SV-88793' do
  title 'The Cisco IOS XE router must enable neighbor router authentication for control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network, or merely used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and Multicast-related protocols.)
  desc 'check', 'Review the Cisco IOS XE router configuration and verify that neighbor router authentication is configured for all control plane protocols.

The configuration should look similar to the examples below:

OSPF Example:
router ospf 1
area 1 authentication message-digest

interface GigabitEthernet0/0
ip ospf message-digest-key 1 md5 <authentication key>

BGP Example:

router bgp 65001
 bgp log-neighbor-changes
 neighbor 2200:31:3::1 remote-as 65000
 neighbor 2200:31:3::1 password <password>
 neighbor 200.31.3.1 remote-as 65000
 neighbor 200.31.3.1 password <password>

If authentication is not enabled, this is a finding.'
  desc 'fix', 'Configure neighbor router authentication for all control plane protocols. The configuration will look similar to the example below:

OSPF Example:

router ospf 1
 area 1 authentication message-digest

interface GigabitEthernet0/0
 ip ospf message-digest-key 1 md5 <authentication key>

BGP Example:

router bgp 65001
 bgp log-neighbor-changes
 neighbor 2200:31:3::1 remote-as 65000
 neighbor 2200:31:3::1 password <password>
 neighbor 200.31.3.1 remote-as 65000
 neighbor 200.31.3.1 password <password>'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74205r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74119'
  tag rid: 'SV-88793r2_rule'
  tag stig_id: 'CISR-RT-000012'
  tag gtitle: 'SRG-NET-000025-RTR-000020'
  tag fix_id: 'F-80661r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end

control 'SV-80627' do
  title 'The HP FlexFabric Switch must bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.'
  desc 'Protocol Independent Multicast (PIM) is a routing protocol used to build multicast distribution trees for forwarding multicast traffic across the network infrastructure. Protocol Independent Multicast traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those interfaces that have PIM enabled, an unauthorized routers can join the PIM domain and discover and use the rendezvous points, and also advertise their rendezvous points into the domain. This can result in a denial of service by traffic flooding or result in the unauthorized transfer of data.'
  desc 'check', "Review the multicast topology diagram and determine if the HP FlexFabric Switch interfaces are enabled for IPv4 or IPv6 multicast routing. 

If the HP FlexFabric Switch is enabled for multicast routing, verify all interfaces enabled for PIM have a neighbor filter bound to the interface. The neighbor filter must only accept PIM control plane traffic from the documented PIM neighbors. 

If a PIM neighbor filter is not configured on all multicast-enabled interfaces, this is a finding.

display interface GigabitEthernet 0/1

interface GigabitEthernet0/1
 port link-mode route
 description IUT 4GE-HMIM
 ip address 15.252.78.69 255.255.255.0
 pim sm
 pim neighbor-policy 2000
 ipv6 pim sm
ipv6 pim neighbor-policy 2000

[HP]display acl 2000
Basic ACL  2000, named -none-, 3 rules,
ACL's step is 5
 rule 0 permit source 224.200.100.10 0
 rule 5 permit source 224.200.101.11 0
 rule 10 deny"
  desc 'fix', 'Configure neighbor filters to only accept PIM control plane traffic from documented PIM neighbors. Bind neighbor filters to all PIM enabled interfaces using the example bellow.

acl basic 2000
 rule 0 permit source 224.200.100.10 0
 rule 5 permit source 224.200.101.11 0 
 rule 10 deny source any

interface GigabitEthernet0/1
 pim neighbor-policy 2000'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66137'
  tag rid: 'SV-80627r1_rule'
  tag stig_id: 'HFFS-RT-000025'
  tag gtitle: 'SRG-NET-000019-RTR-000004'
  tag fix_id: 'F-72213r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

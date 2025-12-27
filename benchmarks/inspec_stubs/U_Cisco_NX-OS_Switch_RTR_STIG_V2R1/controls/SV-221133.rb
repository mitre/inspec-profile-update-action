control 'SV-221133' do
  title 'The Cisco multicast switch must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.'
  desc 'PIM is a routing protocol used to build multicast distribution trees for forwarding multicast traffic across the network infrastructure. PIM traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those interfaces that have PIM enabled, unauthorized switches can join the PIM domain, discover and use the rendezvous points, and also advertise their rendezvous points into the domain. This can result in a denial of service by traffic flooding or result in the unauthorized transfer of data.'
  desc 'check', 'Step 1: Verify all interfaces enabled for PIM have a neighbor policy bound to the interface as shown in the example below:

interface Ethernet2/1
 no switchport
 ip address 10.1.12.1/24
 ip pim sparse-mode
 ip pim neighbor-policy prefix-list PIM_NEIGHBOR
 no shutdown

Step 2: Review the configured prefix list for filtering PIM neighbors as shown in the example below:

ip prefix-list PIM_NEIGHBOR seq 5 permit 10.1.12.2/32
ip prefix-list PIM_NEIGHBOR seq 10 deny 0.0.0.0/0 le 32

If PIM neighbor ACLs are not bound to all interfaces that have PIM enabled, this is a finding.'
  desc 'fix', 'Configure neighbor prefix lists to only accept PIM control plane traffic from documented PIM neighbors. 

Step 1: Configure prefix list for each PIM neighbor.

SW1(config)# ip prefix-list PIM_NEIGHBOR seq 5 permit 10.1.12.2/32
SW1(config)# ip prefix-list PIM_NEIGHBOR deny 0.0.0.0/0 le 32

Step 2: Apply a prefix to all interfaces enabled for PIM.

SW1(config)# int e2/1
SW1(config-if)# ip pim neighbor-policy prefix-list PIM_NEIGHBOR 
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22848r409888_chk'
  tag severity: 'medium'
  tag gid: 'V-221133'
  tag rid: 'SV-221133r622190_rule'
  tag stig_id: 'CISC-RT-000800'
  tag gtitle: 'SRG-NET-000019-RTR-000004'
  tag fix_id: 'F-22837r409889_fix'
  tag 'documentable'
  tag legacy: ['SV-111085', 'V-101981']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

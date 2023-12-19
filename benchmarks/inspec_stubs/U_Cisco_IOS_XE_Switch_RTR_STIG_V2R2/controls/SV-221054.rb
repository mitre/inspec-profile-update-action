control 'SV-221054' do
  title 'The Cisco multicast switch must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.'
  desc 'PIM is a routing protocol used to build multicast distribution trees for forwarding multicast traffic across the network infrastructure. PIM traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those interfaces that have PIM enabled, unauthorized switches can join the PIM domain, discover and use the rendezvous points, and also advertise their rendezvous points into the domain. This can result in a denial of service by traffic flooding or result in the unauthorized transfer of data.'
  desc 'check', 'Step 1: Verify all interfaces enabled for PIM have a neighbor ACL bound to the interface as shown in the example below:

interface GigabitEthernet1/1
 no switchport
 ip address 10.1.2.2 255.255.255.0
 ip pim neighbor-filter PIM_NEIGHBORS
 ip pim sparse-mode

Step 2: Review the configured ACL for filtering PIM neighbors as shown in the example below:

ip access-list standard PIM_NEIGHBORS
 permit 10.1.2.6

If PIM neighbor ACLs are not bound to all interfaces that have PIM enabled, this is a finding.'
  desc 'fix', 'Configure neighbor ACLs to only accept PIM control plane traffic from documented PIM neighbors. Bind neighbor ACLs to all PIM enabled interfaces.

Step 1: Configure ACL for PIM neighbors.

SW2(config)#ip access-list standard PIM_NEIGHBORS
SW2(config-std-nacl)#permit 10.1.2.6
SW2(config-std-nacl)#exit

Step 2: Apply the ACL to all interfaces enabled for PIM.

SW2(config)#int g1/1
SW2(config-if)#ip pim neighbor-filter PIM_NEIGHBORS'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22769r408956_chk'
  tag severity: 'medium'
  tag gid: 'V-221054'
  tag rid: 'SV-221054r622190_rule'
  tag stig_id: 'CISC-RT-000800'
  tag gtitle: 'SRG-NET-000019-RTR-000004'
  tag fix_id: 'F-22758r408957_fix'
  tag 'documentable'
  tag legacy: ['SV-110929', 'V-101825']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

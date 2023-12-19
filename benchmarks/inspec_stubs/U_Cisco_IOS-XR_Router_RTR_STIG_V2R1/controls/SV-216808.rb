control 'SV-216808' do
  title 'The Cisco multicast router must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.'
  desc 'PIM is a routing protocol used to build multicast distribution trees for forwarding multicast traffic across the network infrastructure. PIM traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those interfaces that have PIM enabled, unauthorized routers can join the PIM domain, discover and use the rendezvous points, and also advertise their rendezvous points into the domain. This can result in a denial of service by traffic flooding or result in the unauthorized transfer of data.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Verify all interfaces enabled for PIM have a neighbor ACL bound to the interface as shown in the example below.

router pim
 address-family ipv4
  interface GigabitEthernet0/0/0/1
   enable
   neighbor-filter PIM_NEIGHBOR_1
  !
  interface GigabitEthernet0/0/0/2
   enable
   neighbor-filter PIM_NEIGHBOR_2
  !
 !
!

Step 2: Review the configured ACL for filtering PIM neighbors as shown in the example below.

ipv4 access-list PIM_NEIGHBOR_1
 10 permit ipv4 host 10.1.1.2 any
!
ipv4 access-list PIM_NEIGHBOR_2
 10 permit ipv4 host 10.1.2.8 any
!

If PIM neighbor ACLs are not bound to all interfaces that have PIM enabled, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure neighbor ACLs to only accept PIM control plane traffic from documented PIM neighbors. Bind neighbor ACLs to all PIM enabled interfaces.

Step 1: Configure ACL for PIM neighbors.

RP/0/0/CPU0:R2(config)#ipv4 access-list PIM_NEIGHBOR_1
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ipv4 host 10.1.1.2 any
RP/0/0/CPU0:R2(config-ipv4-acl)#exit

Step 2: Apply the ACL to all interfaces enabled for PIM.

RP/0/0/CPU0:R2(config)#router pim
RP/0/0/CPU0:R2(config-pim)#address-family ipv4
RP/0/0/CPU0:R2(config-pim-default-ipv4)#int g0/0/0/1
RP/0/0/CPU0:R2(config-pim-ipv4-if)#neighbor-filter PIM_NEIGHBOR_1
RP/0/0/CPU0:R2(config-pim-ipv4-if)#exit
RP/0/0/CPU0:R2(config-pim-default-ipv4)#int g0/0/0/2                  
RP/0/0/CPU0:R2(config-pim-ipv4-if)#neighbor-filter PIM_NEIGHBOR_2
RP/0/0/CPU0:R2(config-pim-ipv4-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18040r288798_chk'
  tag severity: 'medium'
  tag gid: 'V-216808'
  tag rid: 'SV-216808r531087_rule'
  tag stig_id: 'CISC-RT-000800'
  tag gtitle: 'SRG-NET-000019-RTR-000004'
  tag fix_id: 'F-18038r288799_fix'
  tag 'documentable'
  tag legacy: ['V-96823', 'SV-105961']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

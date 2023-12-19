control 'SV-255999' do
  title 'The Arista multicast router must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.'
  desc 'PIM is a routing protocol used to build multicast distribution trees for forwarding multicast traffic across the network infrastructure. PIM traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those interfaces that have PIM enabled, unauthorized routers can join the PIM domain, discover and use the rendezvous points, and also advertise their rendezvous points into the domain. This can result in a denial of service by traffic flooding or result in the unauthorized transfer of data.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Review the Arista router multicast topology diagram and determine if router interfaces are enabled for IPv4 or IPv6 multicast routing.

If the router is enabled for multicast routing, verify all interfaces enabled for PIM have a neighbor filter bound to the interface. The neighbor filter must only accept PIM control plane traffic from the documented PIM neighbors.

Step 1: Verify the ACL is configured that will specify the authorized PIM neighbors. To verify IP access lists are configured, execute the command "show ip access-lists".

ip access-list standard filter_1
  permit 10.13.24.9/24
  exit

Step 2: Verify the PIM neighbor-filter is configured on PIM-enabled interfaces. To verify interfaces are configured, execute the command "show run int YY".

interface vlan 4
  pim ipv4 sparse-mode
  pim ipv4 neighbor-filter filter_1
  exit

If PIM neighbor filters are not bound to all interfaces that have PIM enabled, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure neighbor filters to only accept PIM control plane traffic from documented PIM neighbors. Bind neighbor filters to all PIM-enabled interfaces.

Step 1: Configure an ACL that will specify the authorized PIM neighbors.

router(config)#ip access-list standard filter_1
router(config-std-acl-filter_1)#permit 10.13.24.9/24
router(config-std-acl-filter_1)#exit

Step 2: Configure a PIM neighbor-filter command and apply it on all PIM-enabled interfaces that are referencing the PIM neighbor ACL.

router(config)#interface vlan 4
router(config-if-Vl4)#pim ipv4 neighbor-filter filter_1
router(config-if-Vl4)#exit'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59675r882337_chk'
  tag severity: 'medium'
  tag gid: 'V-255999'
  tag rid: 'SV-255999r882339_rule'
  tag stig_id: 'ARST-RT-000130'
  tag gtitle: 'SRG-NET-000019-RTR-000004'
  tag fix_id: 'F-59618r882338_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

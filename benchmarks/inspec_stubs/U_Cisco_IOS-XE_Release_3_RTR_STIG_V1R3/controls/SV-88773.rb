control 'SV-88773' do
  title 'The Cisco IOS XE router must bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.'
  desc 'Protocol Independent Multicast (PIM) is a routing protocol used to build multicast distribution trees for forwarding multicast traffic across the network infrastructure. Protocol Independent Multicast traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those interfaces that have PIM enabled, an unauthorized routers can join the PIM domain and discover and use the rendezvous points, and also advertise their rendezvous points into the domain. This can result in a denial of service by traffic flooding or result in the unauthorized transfer of data.'
  desc 'check', 'Step 1: Verify that an ACL is configured that will specify the allowable PIM neighbors similar to the following example:

ip access-list standard PIM-NEIGHBORS
permit 192.0.2.1
permit 192.0.2.3

Step 2: Verify that a pim neighbor-filter command is configured on all PIM enabled interfaces that is referencing the PIM neighbor ACL similar to the following example:

interface GigabitEthernet0/3
ip address 192.0.2.2 255.255.255.0
ip pim sparse-mode
pim neighbor-filter PIM-NEIGHBORS

If the Cisco IOS XE router has not been configured with PIM neighbor filter on all PIM-enabled interfaces, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router with PIM neighbor filters on all PIM-enabled interfaces as shown in the example below:

ip access-list standard PIM-NEIGHBORS
permit 192.0.2.1
permit 192.0.2.3
...
...
...
interface GigabitEthernet0/3
ip address 192.0.2.2 255.255.255.0
ip pim sparse-mode
ip pim neighbor-filter PIM-NEIGHBORS'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74185r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74099'
  tag rid: 'SV-88773r2_rule'
  tag stig_id: 'CISR-RT-000003'
  tag gtitle: 'SRG-NET-000019-RTR-000004'
  tag fix_id: 'F-80641r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

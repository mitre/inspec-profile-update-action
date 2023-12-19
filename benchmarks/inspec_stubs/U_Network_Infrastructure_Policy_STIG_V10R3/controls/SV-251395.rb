control 'SV-251395' do
  title 'Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) report messages must be filtered to allow hosts to join only those multicast groups that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (e.g., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups that hosts are allowed to join via IGMP (IPv4) or MLD (IPv6).'
  desc 'check', 'Review the configuration of the DR to verify that it is filtering IGMP or MLD report messages allowing hosts to only join those groups that have been approved by the organization.

If the DR is not filtering IGMP or MLD report messages, this is a finding.

The following is a PIM sparse mode configuration example filtering specific multicast groups as defined in access-list 11 on the LAN-facing interface.

ip multicast-routing
! 
interface FastEthernet 0/0 
description link to core
ip address 192.168.123.2 255.255.255.0
ip pim sparse-mode 
! 
interface FastEthernet 0/1
description User LAN
ip address 192.168.122.1 255.255.255.0
ip pim sparse-mode 
ip igmp access-group 11
!
access-list 11 permit 224.10.10.0 0.0.0.255
access-list 11 permit 224.11.11.0 0.0.0.255
access-list 11 permit 224.20.20.0 0.0.0.255'
  desc 'fix', 'Configure the Designated Router (DR) to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) report messages to allow tenant hosts to join only those multicast groups that have been approved by the organization.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54830r806138_chk'
  tag severity: 'low'
  tag gid: 'V-251395'
  tag rid: 'SV-251395r806140_rule'
  tag stig_id: 'NET2013'
  tag gtitle: 'NET2013'
  tag fix_id: 'F-54783r806139_fix'
  tag 'documentable'
  tag legacy: ['V-66381', 'SV-80871']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

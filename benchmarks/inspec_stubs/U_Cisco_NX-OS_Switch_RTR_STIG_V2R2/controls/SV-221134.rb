control 'SV-221134' do
  title 'The Cisco multicast edge switch must be configured to establish boundaries for administratively scoped multicast traffic.'
  desc 'If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel.

Administrative scoped multicast addresses are locally assigned and are to be used exclusively by the enterprise network or enclave. Administrative scoped multicast traffic must not cross the enclave perimeter in either direction. Restricting multicast traffic makes it more difficult for a malicious user to access sensitive traffic.

Admin-Local scope is encouraged for any multicast traffic within a network intended for network management, as well as for control plane traffic that must reach beyond link-local destinations.'
  desc 'check', 'Multicast boundary for NX-OS can be established via combination of the border command along with an ACL to filter admin-scoped multicast traffic.

Step 1: Verify that the interface at the multicast domain edge has been configured with both an ingress and egress ACL.

interface Ethernet2/1
 no switchport
 ip access-group FILTER_TRAFFIC_IN in
 ip access-group FILTER_TRAFFIC_OUT out
 ip address 10.1.12.1/24
 ip pim sparse-mode
 ip pim border

Note: The command ip pim border enables the interface to be on the border of PIM domain so that no bootstrap, candidate-RP, or Auto-RP messages are sent or received on the interface. 

Step 2: Verify that the ingress and egress ACLs block the address range for administratively scoped multicast traffic.

ip access-list FILTER_TRAFFIC_IN
 10 deny ip any 239.0.0.0/8
 20 permit tcp any any established
…
 …
 …
90 deny ip any any log 

ip access-list FILTER_TRAFFIC_OUT
 10 deny ip any 239.0.0.0/8
 20 deny ip …
 …
80 permit ip any any

If the switch is not configured to establish boundaries for administratively scoped multicast traffic, this is a finding.'
  desc 'fix', 'Step 1: Configure an ingress and egress ACL to block administratively scoped multicast traffic.

SW1(config)# ip access-list FILTER_TRAFFIC_IN
SW1(config-acl)# deny 239.0.0.0/8
SW1(config-acl)# permit tcp any any established
SW1(config-acl)# …
SW1(config-acl)# deny ip any any log 
SW1(config-acl)# exit
SW1(config)# ip access-list FILTER_TRAFFIC_OUT
SW1(config-acl)# deny 239.0.0.0/8
SW1(config-acl)# …
SW1(config-acl)# permit ip any any
SW1(config-acl)# exit

Step 2: Apply the ingress and egress ACL to the applicable interfaces.

SW1(config)# int e2/1
SW1(config-if)# ip access-group FILTER_TRAFFIC_IN in
SW1(config-if)# ip access-group FILTER_TRAFFIC_OUT out
SW1(config-if)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22849r409891_chk'
  tag severity: 'low'
  tag gid: 'V-221134'
  tag rid: 'SV-221134r622190_rule'
  tag stig_id: 'CISC-RT-000810'
  tag gtitle: 'SRG-NET-000019-RTR-000005'
  tag fix_id: 'F-22838r409892_fix'
  tag 'documentable'
  tag legacy: ['SV-111087', 'V-101983']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

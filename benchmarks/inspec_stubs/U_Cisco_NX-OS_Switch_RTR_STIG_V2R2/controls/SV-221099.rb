control 'SV-221099' do
  title 'The Cisco perimeter switch must be configured to block all outbound management traffic.'
  desc 'For in-band management, the management network must have its own subnet in order to enforce control and access boundaries provided by Layer 3 network nodes, such as switches and firewalls. Management traffic between the managed network elements and the management network is routed via the same links and nodes as that used for production or operational traffic. Safeguards must be implemented to ensure that the management traffic does not leak past the perimeter of the managed network.'
  desc 'check', 'The perimeter switch of the managed network must be configured with an outbound ACL on the egress interface to block all management traffic as shown in the example below:

Step 1: Verify that all external interfaces has been configured with an outbound ACL as shown in the example below:

interface Ethernet2/2
 description link to DISN
 no switchport
 ip access-group EXTERNAL_ACL_OUTBOUND out
 ip address x.11.1.2 255.255.255.254

Step 2: Verify that the outbound ACL discards management traffic as shown in the example below:

ip access-list EXTERNAL_ACL_OUTBOUND
 10 deny tcp any any eq tacacs log 
 20 deny tcp any any eq 22 log 
 30 deny udp any any eq snmp log 
 40 deny udp any any eq snmptrap log 
 50 deny udp any any eq syslog log 
 60 permit tcp any any eq www log 
 70 deny ip any any log

If management traffic is not blocked at the perimeter, this is a finding.'
  desc 'fix', 'Configure the perimeter switch of the managed network with an outbound ACL on the egress interface to block all management traffic.

Step 1: Configure an ACL to block egress management traffic.

SW1(config)# ip access-list EXTERNAL_ACL_OUTBOUND
SW1(config-acl)# deny tcp any any eq tacacs log
SW1(config-acl)# deny tcp any any eq 22 log
SW1(config-acl)# deny udp any any eq snmp log
SW1(config-acl)# deny udp any any eq snmptrap log
SW1(config-acl)# deny udp any any eq syslog log
SW1(config-acl)# permit tcp any any eq www
SW1(config-acl)# deny ip any any log
SW1(config-acl)# exit

Note: Permit commands would be configured to allow applicable outbound traffic. The example above is allowing web traffic.

Step 2: Configure the external interfaces with the outbound ACL.

SW1(config)#int e2/2
SW1(config-if)# ip access-group EXTERNAL_ACL_OUTBOUND out'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22814r409786_chk'
  tag severity: 'medium'
  tag gid: 'V-221099'
  tag rid: 'SV-221099r622190_rule'
  tag stig_id: 'CISC-RT-000390'
  tag gtitle: 'SRG-NET-000364-RTR-000113'
  tag fix_id: 'F-22803r409787_fix'
  tag 'documentable'
  tag legacy: ['SV-111017', 'V-101913']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end

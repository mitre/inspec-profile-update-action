control 'SV-216767' do
  title 'The Cisco perimeter router must be configured to block all outbound management traffic.'
  desc 'For in-band management, the management network must have its own subnet in order to enforce control and access boundaries provided by Layer 3 network nodes, such as routers and firewalls. Management traffic between the managed network elements and the management network is routed via the same links and nodes as that used for production or operational traffic. Safeguards must be implemented to ensure that the management traffic does not leak past the perimeter of the managed network.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

The perimeter router of the managed network must be configured with an outbound ACL on the egress interface to block all management traffic as shown in the example below.

Step 1: Verify that all external interfaces has been configured with an outbound ACL as shown in the example below.

interface GigabitEthernet0/0/0/2
 ipv4 address 10.1.35.3 255.255.255.0
 ipv4 access-group EXTERNAL_ACL_OUTBOUND egress

Step 2: Verify that the outbound ACL discards management traffic as shown in the example below.

ipv4 access-list EXTERNAL_ACL_OUTBOUND
 10 deny tcp any any eq tacacs log-input
 20 deny tcp any any eq ssh log-input
 30 deny udp any any eq snmp log-input
 40 deny udp any any eq snmptrap log-input
 50 deny udp any any eq syslog log-input
 60 permit tcp any any eq www log-input
 70 deny ipv4 any any log-input

If management traffic is not blocked at the perimeter, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the perimeter router of the managed network with an outbound ACL on the egress interface to block all management traffic.

Step 1: Configure an ACL to block egress management traffic.

RP/0/0/CPU0:R3(config)#Ipv4 access-list EXTERNAL_ACL_OUTBOUND
RP/0/0/CPU0:R3(config-ipv4-acl)#deny   tcp any any eq tacacs log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#deny   tcp any any eq 22 log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#deny   udp any any eq snmp log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#deny   udp any any eq snmptrap log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#deny   udp any any eq syslog log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp any any eq www log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#deny   ip any any log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#end

Note: Permit commands would be configured to allow applicable outbound traffic. The example above  is allowing web traffic.

Step 2: Configure the external interfaces with the outbound ACL.

RP/0/0/CPU0:R3(config)#int g0/0/0/2
RP/0/0/CPU0:R3(config-if)#ipv4 access-group EXTERNAL_ACL_OUTBOUND egress'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17999r288684_chk'
  tag severity: 'medium'
  tag gid: 'V-216767'
  tag rid: 'SV-216767r531087_rule'
  tag stig_id: 'CISC-RT-000390'
  tag gtitle: 'SRG-NET-000364-RTR-000113'
  tag fix_id: 'F-17997r288685_fix'
  tag 'documentable'
  tag legacy: ['SV-105879', 'V-96741']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end

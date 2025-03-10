control 'SV-220452' do
  title 'The Cisco perimeter switch must be configured to block all outbound management traffic.'
  desc 'For in-band management, the management network must have its own subnet in order to enforce control and access boundaries provided by Layer 3 network nodes, such as switches and firewalls. Management traffic between the managed network elements and the management network is routed via the same links and nodes as that used for production or operational traffic. Safeguards must be implemented to ensure that the management traffic does not leak past the perimeter of the managed network.'
  desc 'check', 'Verify that the perimeter switch of the managed network is configured with an outbound ACL on the egress interface to block all management traffic as shown in the example below: 

Step 1: Verify that all external interfaces has been configured with an outbound ACL as shown in the example below: 

interface GigabitEthernet0/2 
 description link to DISN 
 ip address x.11.1.2 255.255.255.254 
 ip access-group EXTERNAL_ACL_OUTBOUND out 

Step 2: Verify that the outbound ACL discards management traffic as shown in the example below: 

ip access-list extended EXTERNAL_ACL_OUTBOUND 
 deny tcp any any eq tacacs log-input 
 deny tcp any any eq 22 log-input 
 deny udp any any eq snmp log-input 
 deny udp any any eq snmptrap log-input 
 deny udp any any eq syslog log-input 
 permit tcp any any eq www log-input 
 deny ip any any log-input 

If management traffic is not blocked at the perimeter, this is a finding.'
  desc 'fix', 'Configure the perimeter switch of the managed network with an outbound ACL on the egress interface to block all management traffic. 

Step 1: Configure an ACL to block egress management traffic. 

SW1(config)#ip access-list extended EXTERNAL_ACL_OUTBOUND 
SW1(config-ext-nacl)#deny tcp any any eq tacacs log-input 
SW1(config-ext-nacl)#deny tcp any any eq 22 log-input 
SW1(config-ext-nacl)#deny udp any any eq snmp log-input 
SW1(config-ext-nacl)#deny udp any any eq snmptrap log-input 
SW1(config-ext-nacl)#deny udp any any eq syslog log-input 
SW1(config-ext-nacl)#permit tcp any any eq www 
SW1(config-ext-nacl)#deny ip any any log-input 
SW1(config-ext-nacl)#exit 

Note: Permit commands would be configured to allow applicable outbound traffic. The example above is allowing web traffic. 

Step 2: Configure the external interfaces with the outbound ACL. 

SW1(config)#int g0/2 
SW1(config-if)#ip access-group EXTERNAL_ACL_OUTBOUND out'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22167r508435_chk'
  tag severity: 'medium'
  tag gid: 'V-220452'
  tag rid: 'SV-220452r622190_rule'
  tag stig_id: 'CISC-RT-000390'
  tag gtitle: 'SRG-NET-000364-RTR-000113'
  tag fix_id: 'F-22156r508436_fix'
  tag 'documentable'
  tag legacy: ['SV-110751', 'V-101647']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end

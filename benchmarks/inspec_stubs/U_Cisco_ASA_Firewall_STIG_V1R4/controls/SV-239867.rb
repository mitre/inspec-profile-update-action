control 'SV-239867' do
  title 'The Cisco ASA perimeter firewall must be configured to block all outbound management traffic.'
  desc "The management network must still have its own subnet in order to enforce control and access boundaries provided by Layer 3 network nodes such as routers and firewalls. Management traffic between the managed network elements and the management network is routed via the same links and nodes as that used for production or operational traffic. 

Safeguards must be implemented to ensure that the management traffic does not leak past the managed network's premise equipment. If a firewall is located behind the premise router, all management traffic must be blocked at that point, with the exception of management traffic destined to premise equipment."
  desc 'check', 'Review the ASA configuration to determine if it blocks outbound management traffic.

Step 1: Verify that an ingress ACL has been applied to all internal interfaces as shown in the example below.

 interface GigabitEthernet0/0
 nameif INSIDE
 security-level 100
 ip address x.1.11.1 255.255.255.0
…
…
…
access-group INSIDE_IN in interface INSIDE

Step 2: Verify that the ingress ACL blocks outbound management traffic as shown in the example below.

access-list INSIDE_IN extended deny udp any any eq snmp 
access-list INSIDE_IN extended deny udp any any eq snmptrap
access-list INSIDE_IN extended deny udp any any eq ntp 
access-list INSIDE_IN extended deny udp any any eq syslog
access-list INSIDE_IN extended deny tcp any any eq 22 
access-list INSIDE_IN extended deny tcp any any eq tacacs
access-list INSIDE_IN extended permit ip any any 

Note: An exception is to allow management traffic destined to perimeter devices. In those cases, configure permit statements for that traffic before the deny statements in the example above.

If the ASA is not configured to block outbound management traffic, this is a finding.'
  desc 'fix', 'Step 1: Configure the ingress ACL similar to the example below.

ASA(config)# access-list INSIDE_IN extended deny udp any any eq snmp 
ASA(config)# access-list INSIDE_IN extended deny udp any any eq snmptrap
ASA(config)# access-list INSIDE_IN extended deny udp any any eq ntp 
ASA(config)# access-list INSIDE_IN extended deny udp any any eq syslog
ASA(config)# access-list INSIDE_IN extended deny tcp any any eq 22 
ASA(config)# access-list INSIDE_IN extended deny tcp any any eq tacacs
ASA(config)# access-list INSIDE_IN extended permit ip any any 

Step 2: Apply the ACL inbound on the internal interfaces as shown in the example below.

ASA(config)# access-group INSIDE_IN out interface INSIDE 
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43100r891329_chk'
  tag severity: 'medium'
  tag gid: 'V-239867'
  tag rid: 'SV-239867r891331_rule'
  tag stig_id: 'CASA-FW-000250'
  tag gtitle: 'SRG-NET-000364-FW-000035'
  tag fix_id: 'F-43059r891330_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end

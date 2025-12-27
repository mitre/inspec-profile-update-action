control 'SV-256025' do
  title 'The Arista router must be configured to only permit management traffic that ingresses and egresses the OOBM interface.'
  desc 'The OOBM access router will connect to the management interface of the managed network elements. The management interface can be a true OOBM interface or a standard interface functioning as the management interface. In either case, the management interface of the managed network element will be directly connected to the OOBM network.

An OOBM interface does not forward transit traffic, thereby providing complete separation of production and management traffic. Since all management traffic is immediately forwarded into the management network, it is not exposed to possible tampering. The separation also ensures that congestion or failures in the managed network do not affect the management of the device. If the device does not have an OOBM port, the interface functioning as the management interface must be configured so that management traffic does not leak into the managed network and that production traffic does not leak into the management network.'
  desc 'check', 'Step 1: To verify the Arista router managed interface has an inbound and outbound ACL configured, execute "show run int Eth YY".

router#show interface Ethernet 3
interface ethernet 3
 ip access-group FILTER_INBOUND in
 ip access-group FILTER_OUTBOUND out

Step 2: To verify the ingress filter only allows management, IGP, and ICMP traffic, execute "show ip access-list".

router#show ip access-list
ip access-list FILTER_INBOUND
   10 permit ospf any any
   20 permit icmp any any echo
   30 permit icmp any any echo-reply
   40 permit ip 10.10.10.0/24 any
   50 deny ip any any log
!
ip access-list FILTER_OUTBOUND
   10 permit ospf any any
   20 permit icmp any any echo
   30 permit icmp any any echo-reply
   40 permit ip any 10.10.10.0/24
   50 deny ip any any log
!

Note: If the management interface is a true OOBM interface, this requirement is not applicable.

If the Arista router does not restrict traffic that ingresses and egresses the management interface, this is a finding.'
  desc 'fix', 'If the Arista management interface is a routed interface, it must be configured with both an ingress and egress ACL.

Step 1: Configure the ingress filter to only allow management, IGP, and ICMP traffic.

LEAF-1A(config)#ip access-list FILTER_INBOUND
LEAF-1A(config-acl-FILTER_INBOUND)#permit ospf any any 
LEAF-1A(config-acl-FILTER_INBOUND)#permit icmp any any echo
LEAF-1A(config-acl-FILTER_INBOUND)#permit icmp any any echo-reply 
LEAF-1A(config-acl-FILTER_INBOUND)#permit ip 10.10.10.0/24 any
LEAF-1A(config-acl-FILTER_INBOUND)#deny ip any any log

Step 2: Configure the outbound filter to only allow management, IGP, and ICMP traffic.

LEAF-1A(config)#ip access-list FILTER_OUTBOUND
LEAF-1A(config-acl-FILTER_OUTBOUND)#permit ospf any any 
LEAF-1A(config-acl-FILTER_OUTBOUND)#permit icmp any any echo
LEAF-1A(config-acl-FILTER_OUTBOUND)#permit icmp any any echo-reply 
LEAF-1A(config-acl-FILTER_OUTBOUND)#permit ip any 10.10.10.0/24
LEAF-1A(config-acl-FILTER_OUTBOUND)#deny ip any any log

Step 3: Set the managed interface to have an inbound and outbound ACL configured.

LEAF-1A(config)#interface ethernet 3
LEAF-1A(config-if-Et3)# ip access-group FILTER_INBOUND in
LEAF-1A(config-if-Et3)# ip access-group FILTER_OUTBOUND out'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59701r882415_chk'
  tag severity: 'medium'
  tag gid: 'V-256025'
  tag rid: 'SV-256025r882417_rule'
  tag stig_id: 'ARST-RT-000440'
  tag gtitle: 'SRG-NET-000205-RTR-000012'
  tag fix_id: 'F-59644r882416_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end

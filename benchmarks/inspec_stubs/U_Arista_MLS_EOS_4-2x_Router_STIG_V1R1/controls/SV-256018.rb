control 'SV-256018' do
  title 'The Arista perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.'
  desc 'Access lists are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of routers makes use of access lists for restricting access to services on the router itself as well as for filtering traffic passing through the router.

Inbound versus Outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The router can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.

'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Review the Arista router configuration to verify the ingress ACL is bound to the external interface in an inbound direction.

Step 1: To verify the ingress ACL is bound to the external interface in an inbound direction, execute the command "sh ip access-list".

ip access-list INBOUND
   10 permit tcp 10.10.10.0/24 host 10.20.10.1 eq ssh telnet
   20 permit ip 10.10.10.0/24 192.168.10.0/24 
   30 permit udp 10.20.20.0/24 any eq bootps snmp

Step 2: To verify the ACL is applied inbound on all external interfaces, execute the command "sh run int Eth YY".

interface ethernet 13
  ip access-group INBOUND in

If the Arista router is not configured to filter traffic entering the network at the external interface in an inbound direction, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Bind the ingress ACL to the external interface (inbound).

Step 1: Configure the ACL.

LEAF-1A(config)#ip access-list INBOUND
LEAF-1A(config-acl-INBOUND)#10 permit tcp 10.10.10.0/24 host 10.20.10.1 eq ssh telnet
LEAF-1A(config-acl-INBOUND)#20 permit ip 10.10.10.0/24 192.168.10.0/24 
LEAF-1A(config-acl-INBOUND)#30 permit udp 10.20.20.0/24 any eq bootps snmp
LEAF-1A(config-acl-INBOUND)#40 deny ip any any log

Step 2: Apply the ACL inbound on all external interfaces.

LEAF-1A(config)#interface ethernet 13
LEAF-1A(config-if-Et13)#ip access-group INBOUND in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59694r882394_chk'
  tag severity: 'medium'
  tag gid: 'V-256018'
  tag rid: 'SV-256018r882396_rule'
  tag stig_id: 'ARST-RT-000370'
  tag gtitle: 'SRG-NET-000205-RTR-000003'
  tag fix_id: 'F-59637r882395_fix'
  tag satisfies: ['SRG-NET-000205-RTR-000003', 'SRG-NET-000205-RTR-000004']
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end

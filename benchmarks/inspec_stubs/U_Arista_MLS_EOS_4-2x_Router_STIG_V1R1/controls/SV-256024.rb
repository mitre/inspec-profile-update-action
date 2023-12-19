control 'SV-256024' do
  title 'The out-of-band management (OOBM) Arista gateway router must be configured to block any traffic destined to itself that is not sourced from the OOBM network or the NOC.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries. It is imperative that hosts from the managed network are not able to access the OOBM gateway router.'
  desc 'check', %q(This requirement is not applicable for the DODIN backbone.

Review the access control list (ACL) or filter for the router receive path.

Verify only traffic sourced from the OOBM network or the NOC is allowed to access the router.

Note: If the platform does not support the receive path filter, verify all non-OOBM interfaces have an ingress ACL to restrict access to that interface address or any of the router's loopback addresses to only traffic sourced from the management network. An exception would be to allow packets destined to these interfaces used for troubleshooting, such as ping and traceroute.

Step 1: To verify the ACL is configured, execute "show ip access-list OOBM_ACL".

Step 2: Determine the NOC management network subnet, which is 172.16.12.0/24.

Step 3: Verify the ACL restricts all management plane traffic.

ip access-list OOBM_ACL
   permit tcp 192.168.10.0/24 any eq ssh
   permit udp host 172.16.12.42 any eq snmp
   permit udp host 172.16.12.41 any eq ntp
   permit icmp 172.16.12.0/24 any
   deny ip any any log

Step 4: To verify the ACL is applied ingress on the OOBM interface, execute the command "sh run int Eth YY".

interface ethernet 1
  description LAN link
  ip access-group OOBM_ACL in

If the Arista router does not block any traffic destined to itself that is not sourced from the OOBM network or the NOC, this is a finding.)
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Ensure traffic from the managed network is not able to access the OOBM gateway router using either receive path or interface ingress ACLs.

Step 1: Configure the ACL to restrict all management plane traffic.

ip access-list OOBM_ACL
   permit tcp 192.168.10.0/24 any eq ssh
   permit udp host 172.16.12.42 any eq snmp
   permit udp host 172.16.12.41 any eq ntp
   permit icmp 172.16.12.0/24 any
   deny ip any any log

Step 2: Apply the ACL ingress. Execute the command "sh run int Eth YY".

interface ethernet 1
  description LAN link
  ip access-group OOBM_ACL in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59700r882412_chk'
  tag severity: 'medium'
  tag gid: 'V-256024'
  tag rid: 'SV-256024r882414_rule'
  tag stig_id: 'ARST-RT-000430'
  tag gtitle: 'SRG-NET-000205-RTR-000011'
  tag fix_id: 'F-59643r882413_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end

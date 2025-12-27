control 'SV-221087' do
  title 'The Cisco perimeter switch must be configured to deny network traffic by default and allow network traffic by exception.'
  desc 'A deny-all, permit-by-exception network communications traffic policy ensures that only connections that are essential and approved are allowed.

This requirement applies to both inbound and outbound network communications traffic. All inbound and outbound traffic must be denied by default. Firewalls and perimeter switches should only allow traffic through that is explicitly permitted. The initial defense for the internal network is to block any traffic at the perimeter that is attempting to make a connection to a host residing on the internal network. In addition, allowing unknown or undesirable outbound traffic by the firewall or switch will establish a state that will permit the return of this undesirable traffic inbound.'
  desc 'check', 'Review the switch configuration to verify that the inbound ACL applied to all external interfaces is configured to allow specific ports and protocols and deny all other traffic.

Step 1: Verify that an inbound ACL is applied to all external interfaces as shown in the example below:

interface Ethernet1/2
 no switchport
 ip access-group EXTERNAL_ACL in
 ip address x.11.1.2 255.255.255.254

Step 2: Review inbound ACL to verify that it is configured to deny all other traffic that is not explicitly allowed.

ip access-list EXTERNAL_ACL
 10 permit tcp x.11.1.1/32 eq bgp x.11.1.2/32 
 20 permit tcp x.11.1.1/32 x.11.1.2/32 eq bgp 
 30 permit icmp x.11.1.1/32 x.11.1.2/32 echo 
 40 permit icmp x.11.1.1/32 x.11.1.2/32 echo-reply 
 50 permit tcp any x.11.2.3/32 eq www 
 60 permit … 
 …
 …
 …
90 deny ip any any log

If the ACL is not configured to allow specific ports and protocols and deny all other traffic, this is a finding. If the ACL is not configured inbound on all external interfaces, this is a finding.'
  desc 'fix', 'Step 1: Configure an inbound ACL to deny all other traffic by default as shown in the example below:

SW1(config)# ip access-list EXTERNAL_ACL
SW1(config-acl)# permit tcp host x.11.1.1 eq bgp host x.11.1.2 
SW1(config-acl)# permit tcp host x.11.1.1 host x.11.1.2 eq bgp
SW1(config-acl)# permit icmp host x.11.1.1 host x.11.1.2 echo
SW1(config-acl)# permit icmp host x.11.1.1 host x.11.1.2 echo-reply
SW1(config-acl)# permit tcp any x.11.2.3/32 eq www
SW1(config-acl)# permit …
…
…
…
SW1(config-acl)# deny ip any any log

Step 2: Apply the ingress filter to all external interfaces.

SW1(config)#int e1/2
SW1(config-if)#ip access-group EXTERNAL_ACL in'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22802r409750_chk'
  tag severity: 'high'
  tag gid: 'V-221087'
  tag rid: 'SV-221087r622190_rule'
  tag stig_id: 'CISC-RT-000240'
  tag gtitle: 'SRG-NET-000202-RTR-000001'
  tag fix_id: 'F-22791r409751_fix'
  tag 'documentable'
  tag legacy: ['SV-110993', 'V-101889']
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end

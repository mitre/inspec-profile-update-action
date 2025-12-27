control 'SV-216662' do
  title 'The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception.'
  desc 'A deny-all, permit-by-exception network communications traffic policy ensures that only connections that are essential and approved are allowed.

This requirement applies to both inbound and outbound network communications traffic. All inbound and outbound traffic must be denied by default. Firewalls and perimeter routers should only allow traffic through that is explicitly permitted. The initial defense for the internal network is to block any traffic at the perimeter that is attempting to make a connection to a host residing on the internal network. In addition, allowing unknown or undesirable outbound traffic by the firewall or router will establish a state that will permit the return of this undesirable traffic inbound.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that the inbound ACL applied to all external interfaces is configured to allow specific ports and protocols and deny all other traffic.

Step 1: Verify that an inbound ACL is applied to all external interfaces as shown in the example below:

interface GigabitEthernet0/2
 ip address x.11.1.2 255.255.255.254
 ip access-group EXTERNAL_ACL in

Step 2: Review inbound ACL to verify that it is configured to deny all other traffic that is not explicitly allowed.

ip access-list extended EXTERNAL_ACL
 permit tcp any any established
 permit tcp host x.11.1.1 eq bgp host x.11.1.2
 permit tcp host x.11.1.1 host x.11.1.2 eq bgp
 permit icmp host x.11.1.1 host x.11.1.2 echo
 permit icmp host x.11.1.1 host x.11.1.2 echo-reply
 …
 …
 …
deny   ip any any log-input

If the ACL is not configured to allow specific ports and protocols and deny all other traffic, this is a finding. If the ACL is not configured inbound on all external interfaces, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Configure an inbound ACL to deny all other traffic by default as shown in the example below:

R1(config)#ip access-list extended EXTERNAL_ACL
R1(config-ext-nacl)#permit tcp any any established
R1(config-ext-nacl)#permit tcp host x.11.1.1 eq bgp host x.11.1.2    
R1(config-ext-nacl)#permit tcp host x.11.1.1 host x.11.1.2 eq bgp
R1(config-ext-nacl)#permit icmp host x.11.1.1 host x.11.1.2 echo
R1(config-ext-nacl)#permit icmp host x.11.1.1 host x.11.1.2 echo-reply
…
…
…
R1(config-ext-nacl)#deny ip any any log-input

Step 2: Apply the ingress filter to all external interfaces.

R1(config)#int g0/2
R1(config-if)#ip access-group EXTERNAL_ACL in'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17895r287943_chk'
  tag severity: 'high'
  tag gid: 'V-216662'
  tag rid: 'SV-216662r531086_rule'
  tag stig_id: 'CISC-RT-000240'
  tag gtitle: 'SRG-NET-000202-RTR-000001'
  tag fix_id: 'F-17893r287944_fix'
  tag 'documentable'
  tag legacy: ['SV-106035', 'V-96897']
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end

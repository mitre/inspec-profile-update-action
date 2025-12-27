control 'SV-216752' do
  title 'The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception.'
  desc 'A deny-all, permit-by-exception network communications traffic policy ensures that only connections that are essential and approved are allowed.

This requirement applies to both inbound and outbound network communications traffic. All inbound and outbound traffic must be denied by default. Firewalls and perimeter routers should only allow traffic through that is explicitly permitted. The initial defense for the internal network is to block any traffic at the perimeter that is attempting to make a connection to a host residing on the internal network. In addition, allowing unknown or undesirable outbound traffic by the firewall or router will establish a state that will permit the return of this undesirable traffic inbound.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that the inbound ACL applied to all external interfaces is configured to allow specific ports and protocols and deny all other traffic.

Step 1: Verify that an inbound ACL is applied to all external interfaces as shown in the example below.

interface GigabitEthernet0/0/0/1
 ipv4 address x.11.1.2 255.255.255.252
 ipv4 access-group EXTERNAL_ACL_INBOUND ingress

Step 2: Review inbound ACL to verify that it is configured to deny all other traffic that is not explicitly allowed.

ipv4 access-list EXTERNAL_ACL_INBOUND
 10 permit tcp host x.11.1.1 eq bgp host x.11.1.2
 20 permit tcp host x.11.1.1 host x.11.1.2 eq bgp
 30 permit icmp host x.11.1.1 host x.11.1.2 echo
 40 permit icmp host x.11.1.1 host x.11.1.2 echo-reply
 50 deny ipv4 any host x.11.1.1 log-input 
 60 permit tcp any any established
 …
 …
 …
 140 deny ipv4 any any log-input 

If the ACL is not configured to allow specific ports and protocols and deny all other traffic, this is a finding. If the ACL is not configured inbound on all external interfaces, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Configure an inbound ACL to deny all other traffic by default as shown in the example below.

RP/0/0/CPU0:R3(config)#ipv4 access-list EXTERNAL_ACL_INBOUND
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp host x.11.1.1 eq bgp host x.11.1.2
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp host x.11.1.1 host x.11.1.2 eq bgp
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp host x.11.1.1 host x.11.1.2 echo
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp host x.11.1.1 host x.11.1.2 echo-reply
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ip any host x.11.1.1 log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp any any established
…
…
…
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ip any any log-input 
RP/0/0/CPU0:R3(config-ipv4-acl)#exit

Step 2: Apply the ingress filter to all external interfaces

RP/0/0/CPU0:R3(config)#int g0/0/0/1  
RP/0/0/CPU0:R3(config-if)#ipv4 access-group EXTERNAL_ACL_INBOUND in
RP/0/0/CPU0:R3(config-if)#end'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17984r288645_chk'
  tag severity: 'high'
  tag gid: 'V-216752'
  tag rid: 'SV-216752r531087_rule'
  tag stig_id: 'CISC-RT-000240'
  tag gtitle: 'SRG-NET-000202-RTR-000001'
  tag fix_id: 'F-17982r288646_fix'
  tag 'documentable'
  tag legacy: ['V-96711', 'SV-105849']
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end

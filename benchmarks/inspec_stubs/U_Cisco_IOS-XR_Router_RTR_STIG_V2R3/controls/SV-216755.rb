control 'SV-216755' do
  title 'The Cisco perimeter router must be configured to block inbound packets with source Bogon IP address prefixes.'
  desc 'Packets with Bogon IP source addresses should never be allowed to traverse the IP core. Bogon IP networks are RFC1918 addresses or address blocks that have never been assigned by the IANA or have been reserved.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that an ingress ACL applied to all external interfaces is blocking packets with Bogon source addresses.

Step 1: Verify an ACL has been configured containing the current Bogon prefixes as shown in the example below.

ipv4 access-list EXTERNAL_ACL_INBOUND
 10 deny ipv4 0.0.0.0 0.255.255.255 any log-input
 20 deny ipv4 10.0.0.0 0.255.255.255 any log-input
 30 deny ipv4 100.64.0.0 0.63.255.255 any log-input
 40 deny ipv4 127.0.0.0 0.255.255.255 any log-input
 50 deny ipv4 169.254.0.0 0.0.255.255 any log-input
 60 deny ipv4 172.16.0.0 0.15.255.255 any log-input
 70 deny ipv4 192.0.0.0 0.0.0.255 any log-input
 80 deny ipv4 192.0.2.0 0.0.0.255 any log-input
 90 deny ipv4 192.168.0.0 0.0.255.255 any log-input
 100 deny ipv4 198.18.0.0 0.1.255.255 any log-input
 110 deny ipv4 198.51.100.0 0.0.0.255 any log-input
 120 deny ipv4 203.0.113.0 0.0.0.255 any log-input
 130 deny ipv4 224.0.0.0 31.255.255.255 any log-input
 140 permit tcp any any established
 150 permit tcp host x.12.1.9 host x.12.1.10 eq bgp
 160 permit tcp host x.12.1.9 eq bgp host x.12.1.10
 170 permit icmp host x.12.1.9 host x.12.1.10 echo
 180 permit icmp host x.12.1.9 host x.12.1.10 echo-reply
 …
 …
 …
 260 deny ipv4 any any log-input

External Interfaces connected to the NIPRNet or SIPRNet

Review the inbound ACLs on external facing interfaces attached to the NIPRNet or SIPRNet to validate access control lists are configured to block inbound packets with IP sources addresses as documented in RFC5735 and RFC6598. 

External Interfaces connected to a commercial ISP or other non-DoD network
 
Review the inbound ACLs on external facing interfaces validate access control lists are configured to block inbound packets with IP sources addresses as documented in RFC5735 and RFC6598 as well as address space that has been allocated to the RIRs but not assigned by the RIR to an ISP or other enterprise network. The full list of bogons can be found at the following link: www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt

Step 2: Verify that the inbound ACL applied to all external interfaces will block all traffic from Bogon source addresses.

interface GigabitEthernet0/0/0/1
 ipv4 address x.12.1.10 255.255.255.2
 ipv4 access-group EXTERNAL_ACL_INBOUND ingress

If the router is not configured to block inbound packets with source Bogon IP addresses, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the perimeter to block inbound packets with Bogon source addresses.

Step 1: Configure an ACL containing the current Bogon prefixes as shown below.

RP/0/0/CPU0:R2(config)#ipv4 access-list EXTERNAL_ACL_INBOUND
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 0.0.0.0 0.255.255.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 10.0.0.0 0.255.255.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 100.64.0.0 0.63.255.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 127.0.0.0 0.255.255.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 169.254.0.0 0.0.255.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 172.16.0.0 0.15.255.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 192.0.0.0 0.0.0.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 192.0.2.0 0.0.0.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 192.168.0.0 0.0.255.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 198.18.0.0 0.1.255.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 198.51.100.0 0.0.0.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 203.0.113.0 0.0.0.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip 224.0.0.0 31.255.255.255 any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp any any established
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp host x.12.1.9 host x.12.1.10 eq bgp
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp host x.12.1.9 eq bgp host x.12.1.10
RP/0/0/CPU0:R2(config-ipv4-acl)#permit icmp host x.12.1.9 host x.12.1.10 echo
RP/0/0/CPU0:R2(config-ipv4-acl)#permit icmp host x.12.1.9 host x.12.1.10 echo-reply
…
…
…
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip any any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#end

Step 2: Apply the ACL inbound on all external interfaces.

RP/0/0/CPU0:R3(config)#int g0/0/0/1  
RP/0/0/CPU0:R3(config-if)#ipv4 access-group EXTERNAL_ACL_INBOUND in
RP/0/0/CPU0:R3(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17987r288654_chk'
  tag severity: 'medium'
  tag gid: 'V-216755'
  tag rid: 'SV-216755r856441_rule'
  tag stig_id: 'CISC-RT-000270'
  tag gtitle: 'SRG-NET-000364-RTR-000110'
  tag fix_id: 'F-17985r288655_fix'
  tag 'documentable'
  tag legacy: ['SV-105855', 'V-96717']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end

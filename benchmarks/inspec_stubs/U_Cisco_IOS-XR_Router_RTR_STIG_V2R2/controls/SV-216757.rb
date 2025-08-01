control 'SV-216757' do
  title 'The Cisco perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.'
  desc 'ISPs use BGP to share route information with other autonomous systems (i.e. other ISPs and corporate networks). If the perimeter router was configured to BGP peer with an ISP, NIPRnet routes could be advertised to the ISP, thereby creating a backdoor connection from the Internet to the NIPRnet.'
  desc 'check', "This requirement is not applicable for the DODIN Backbone.

Step 1: Configure the ingress ACL of the perimeter router connected to an alternate gateway to only permit packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider as shown in the example below.

RP/0/0/CPU0:R2(config)#ip access-list ISP_ACL_INBOUND
RP/0/0/CPU0:R2(config-ipv4-acl)# permit tcp any any established
RP/0/0/CPU0:R2(config-ipv4-acl)# permit icmp host x.12.1.16 host x.12.1.17 echo
RP/0/0/CPU0:R2(config-ipv4-acl)# permit icmp host x.12.1.16 host x.12.1.17 echo-reply
RP/0/0/CPU0:R2(config-ipv4-acl)# permit tcp any host x.12.1.22 eq www
RP/0/0/CPU0:R2(config-ipv4-acl)# permit tcp any host x.12.1.23 eq www
RP/0/0/CPU0:R2(config-ipv4-acl)# permit 50 any host x.12.1.24
RP/0/0/CPU0:R2(config-ipv4-acl)# permit 51 any host x.12.1.24
RP/0/0/CPU0:R2(config-ipv4-acl)# deny   ip any any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#end

Step 2: Apply the ACL inbound on the ISP-facing interface.

RP/0/0/CPU0:R3(config)#int g0/0/0/2 
RP/0/0/CPU0:R3(config-if)#ipv4 access-group ISP_ACL_INBOUND in
RP/0/0/CPU0:R3(config-if)#end

If any BGP neighbors belonging to the alternate gateway service provider exist, this is a finding."
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Remove any BGP neighbors belonging to the alternate gateway service provider and configure a static route to forward Internet bound traffic to the alternate gateway as shown in the example below.

R5(config)#ip route 0.0.0.0 0.0.0.0 x.22.1.14'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17989r507362_chk'
  tag severity: 'high'
  tag gid: 'V-216757'
  tag rid: 'SV-216757r531087_rule'
  tag stig_id: 'CISC-RT-000290'
  tag gtitle: 'SRG-NET-000019-RTR-000009'
  tag fix_id: 'F-17987r507363_fix'
  tag 'documentable'
  tag legacy: ['SV-105859', 'V-96721']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

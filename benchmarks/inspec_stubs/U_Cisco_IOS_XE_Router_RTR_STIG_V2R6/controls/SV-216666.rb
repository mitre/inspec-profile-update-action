control 'SV-216666' do
  title 'The Cisco perimeter router must be configured to protect an enclave connected to an alternate gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.'
  desc "Enclaves with alternate gateway connections must take additional steps to ensure there is no compromise on the enclave network or NIPRNet. Without verifying the destination address of traffic coming from the site's alternate gateway, the perimeter router could be routing transit data from the Internet into the NIPRNet. This could also make the perimeter router vulnerable to a denial of service (DoS) attack as well as provide a back door into the NIPRNet. The DoD enclave must ensure the ingress filter applied to external interfaces on a perimeter router connecting to an Approved Gateway is secure through filters permitting packets with a destination address belonging to the DoD enclave's address block."
  desc 'check', "This requirement is not applicable for the DODIN Backbone.

Step 1: Verify the interface connecting to ISP has an inbound ACL as shown in the example below.

interface GigabitEthernet0/2
 description Link to ISP
 ip address x.22.1.15 255.255.255.240
 ip access-group FILTER_ISP in

Step 2: Verify that the ACL only allows traffic to specific destination addresses (i.e. enclave’s NIPRNet address space) as shown in the example below.

ip access-list extended FILTER_ISP
 permit tcp any any established
 permit icmp host x.12.1.16 host x.12.1.17 echo
 permit icmp host x.12.1.16 host x.12.1.17 echo-reply
 permit tcp any host x.12.1.22 eq www
 permit tcp any host x.12.1.23 eq www
 permit 50 any host x.12.1.24
 permit 51 any host x.12.1.24
 deny   ip any any log-input

Note: An Approved Gateway (AG) is any external connection from a DoD NIPRNet enclave to an Internet Service Provider, or network owned by a contractor, or non-DoD federal agency that has been approved by either the DoD CIO or the DoD Component CIO. This AG requirement does not apply to commercial cloud connections when the Cloud Service Provider (CSP) network is connected via the NIPRNet Boundary Cloud Access Point (BCAP).


If the ingress ACL bound to the interface connecting to an alternate gateway permits packets with addresses other than those specified, such as destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider, this is a finding."
  desc 'fix', "This requirement is not applicable for the DODIN Backbone.

Configure the ingress ACL of the perimeter router connected to an alternate gateway to only permit packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider as shown in the example below:

R5(config)#ip access-list extended FILTER_ISP
R5(config-ext-nacl)#permit tcp any any established
R5(config-ext-nacl)#permit icmp host x.12.1.16 host x.12.1.17 echo
R5(config-ext-nacl)#permit icmp host x.12.1.16 host x.12.1.17 echo-reply
R5(config-ext-nacl)#permit tcp any host x.12.1.22 eq www
R5(config-ext-nacl)#permit tcp any host x.12.1.23 eq www
R5(config-ext-nacl)#permit 50 any host x.12.1.24
R5(config-ext-nacl)#permit 51 any host x.12.1.24
R5(config-ext-nacl)#deny ip any any log-input
R5(config-ext-nacl)#end"
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17899r507570_chk'
  tag severity: 'high'
  tag gid: 'V-216666'
  tag rid: 'SV-216666r531086_rule'
  tag stig_id: 'CISC-RT-000280'
  tag gtitle: 'SRG-NET-000019-RTR-000008'
  tag fix_id: 'F-17897r507571_fix'
  tag 'documentable'
  tag legacy: ['SV-106043', 'V-96905']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

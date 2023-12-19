control 'SV-256002' do
  title 'The Arista perimeter router must be configured to protect an enclave connected to an alternate gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.'
  desc "Enclaves with alternate gateway connections must take additional steps to ensure there is no compromise on the enclave network or NIPRNet. Without verifying the destination address of traffic coming from the site's alternate gateway, the perimeter router could be routing transit data from the internet into the NIPRNet. This could also make the perimeter router vulnerable to a denial-of-service (DoS) attack as well as provide a back door into the NIPRNet. The DOD enclave must ensure the ingress filter applied to external interfaces on a perimeter router connecting to an Approved Gateway is secure through filters permitting packets with a destination address belonging to the DOD enclave's address block."
  desc 'check', %q(This requirement is not applicable for the DODIN backbone.

Review the Arista router configuration of each router interface connecting to an alternate gateway.

Verify each permit statement of the ingress filter only permits packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider.

Step 1: Verify an inbound ACL is configured to permit the packets with the destination addresses of the site's NIPRNet address space. Verify IP access lists are configured. Execute the command "show ip access-lists".

ip access-list NIPRNet_ACL
 permit tcp any host 10.51.12.34 eq www
 permit icmp host 10.51.12.25 host 10.51.12.65 echo
 permit icmp host 10.51.12.25 host 10.51.12.65 echo-reply
 permit 50 any host 10.51.12.28
 permit gre any host 10.51.12.28
 deny ip any any log

Step 2: Verify the ACL is applied inbound to the service provider-facing interface. Verify interfaces are configured. Execute the command "show run int YY".

interface ethernet 3
 ip access-group NIPRNet_ACL in

If the ingress filter permits packets with addresses other than those specified, such as destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider, this is a finding.)
  desc 'fix', "This requirement is not applicable for the DODIN backbone.

Configure the router for ingress filter of the perimeter router connected to an alternate gateway to only permit packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider.

Step 1: Configure an ACL inbound to the interface-facing service provider.

LEAF-1A(config)#ip access-list NIPRNet_ACL
LEAF-1A(config-acl-NIPRNet_ACL)#permit tcp any host 10.51.12.34 eq www
LEAF-1A(config-acl-NIPRNet_ACL)#permit icmp host 10.51.12.25 host 10.51.12.65 echo
LEAF-1A(config-acl-NIPRNet_ACL)#permit icmp host 10.51.12.25 host 10.51.12.65 echo-reply
LEAF-1A(config-acl-NIPRNet_ACL)#permit 50 any host 10.51.12.28
LEAF-1A(config-acl-NIPRNet_ACL)#permit gre any host 10.51.12.28
LEAF-1A(config-acl-NIPRNet_ACL)#deny ip any any log

Step 2: Apply the ACL to the internet service provider-facing interface.

LEAF-1A(config)#interface ethernet 3
LEAF-1A(config-if-Et3)#ip access-group NIPRNet_ACL in"
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59678r882346_chk'
  tag severity: 'high'
  tag gid: 'V-256002'
  tag rid: 'SV-256002r882348_rule'
  tag stig_id: 'ARST-RT-000160'
  tag gtitle: 'SRG-NET-000019-RTR-000008'
  tag fix_id: 'F-59621r882347_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

control 'SV-75355' do
  title 'The Arista Multilayer Switch must protect an enclave connected to an Alternate Gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.'
  desc "Enclaves with Alternate Gateway connections must take additional steps to ensure there is no compromise on the enclave network or NIPRNet. Without verifying the destination address of traffic coming from the site's Alternate Gateway, the perimeter router could be routing transit data from the Internet into the NIPRNet. This could also make the perimeter router vulnerable to a DoS attack as well as provide a backdoor into the NIPRNet. The DoD enclave must ensure the ingress filter applied to external interfaces on a perimeter router connecting to an Approved Gateway is secure through filters permitting packets with a destination address belonging to the DoD enclave's address block."
  desc 'check', %q(Review the configuration of each router interface connecting to an Alternate Gateway via the "show running-config" command.

Verify each permit statement of the ingress filter only permits packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the Alternate Gateway network service provider.

If the ingress filter permits packets with addresses other than those specified, such as destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the Alternate Gateway network service provider, this is a finding.)
  desc 'fix', "Configure the ingress filter of the perimeter router connected to an Alternate Gateway to only permit packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the Alternate Gateway network service provider. To configure an example of such a statement, enter:

ip access-list [name]
permit ip [source] [destination]
exit
interface [router interface]
ip access-group [name] in
exit"
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60897'
  tag rid: 'SV-75355r1_rule'
  tag stig_id: 'AMLS-L3-000150'
  tag gtitle: 'SRG-NET-000019-RTR-000009'
  tag fix_id: 'F-66609r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

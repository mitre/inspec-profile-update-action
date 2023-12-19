control 'SV-88781' do
  title 'The Cisco IOS XE router must protect an enclave connected to an Alternate Gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.'
  desc "Enclaves with Alternate Gateway connections must take additional steps to ensure there is no compromise on the enclave network or NIPRNet. Without verifying the destination address of traffic coming from the site's Alternate Gateway, the perimeter router could be routing transit data from the Internet into the NIPRNet. This could also make the perimeter router vulnerable to a DoS attack as well as provide a backdoor into the NIPRNet. The DoD enclave must ensure the ingress filter applied to external interfaces on a perimeter router connecting to an Approved Gateway is secure through filters permitting packets with a destination address belonging to the DoD enclave's address block."
  desc 'check', "Review the configuration of each router interface connecting to an Alternate Gateway on the Cisco IOS XE router.

Verify each permit statement of the ingress filter only permits packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the Alternate Gateway network service provider.

If the ingress filter permits packets with addresses other than those specified, such as destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the Alternate Gateway network service provider, this is a finding."
  desc 'fix', "Configure the Cisco IOS XE router to permit packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the Alternate Gateway network service provider.

The configuration would look similar to the example below:

interface GigabitEthernet 0/0/1
description  Alternate Gateway link
ip address x.x.x.x 255.255.255.0
ip access-group Alternate_Gateway_ACL in
...

ip access-list extended Alternate_Gateway_ACL
permit ip 1.1.1.0 0.0.0.255 any log
..."
  impact 0.7
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74193r2_chk'
  tag severity: 'high'
  tag gid: 'V-74107'
  tag rid: 'SV-88781r2_rule'
  tag stig_id: 'CISR-RT-000006'
  tag gtitle: 'SRG-NET-000019-RTR-000009'
  tag fix_id: 'F-80649r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

control 'SV-80591' do
  title 'The HP FlexFabric Switch must protect an enclave connected to an Alternate Gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.'
  desc "Enclaves with Alternate Gateway (AG) connections must take additional steps to ensure there is no compromise on the enclave network or NIPRNet. Without verifying the destination address of traffic coming from the site's AG, the perimeter router could be routing transit data from the Internet into the NIPRNet. This could also make the perimeter router vulnerable to a DoS attack as well as provide a backdoor into the NIPRNet. The DoD enclave must ensure the ingress filter applied to external interfaces on a perimeter router connecting to an AG is secure through filters permitting packets with a destination address belonging to the DoD enclave's address block."
  desc 'check', "Review the configuration of each HP FlexFabric Switch interface connecting to an Alternate Gateway.

Verify that the ACL configured to block unauthorized networks are configured on the interface.

Verify each permit statement of the ingress filter only permits packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the Alternate Gateway network service provider. 

If the ACL is not configured to only permit packets with destination addresses within the sites address space, this is a finding.

[HP]display interface gig0/1

interface GigabitEthernet0/1
 port link-mode route
 ip address 192.168.10.1 255.255.255.0
 packet-filter 3010 inbound"
  desc 'fix', "Configure the ingress filter of the perimeter HP FlexFabric Switch connected to an Alternate Gateway to only permit packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the Alternate Gateway network service provider.

[HP] acl advanced 3010
[HP-acl-ipv4-adv-3010] rule 1 permit ip destination 192.168.1.0 0.0.0.255
[HP-acl-ipv4-adv-3010] rule 2 permit ip destination 192.168.2.0 0.0.0.255
[HP-acl-ipv4-adv-3010] rule 3 permit ip destination 192.168.3.0 0.0.0.255
[HP-acl-ipv4-adv-3010] rule 4 permit ip destination 192.168.4.0 0.0.0.255
[HP-acl-ipv4-adv-3010] rule 5 deny    ip destination any

[HP] interface gig0/1
[HP-GigabitEthernet0/1] packet-filter 3010 inbound"
  impact 0.7
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66747r1_chk'
  tag severity: 'high'
  tag gid: 'V-66101'
  tag rid: 'SV-80591r1_rule'
  tag stig_id: 'HFFS-RT-000003'
  tag gtitle: 'SRG-NET-000019-RTR-000009'
  tag fix_id: 'F-72177r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

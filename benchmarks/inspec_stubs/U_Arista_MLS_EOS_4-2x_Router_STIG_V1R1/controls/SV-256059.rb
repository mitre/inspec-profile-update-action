control 'SV-256059' do
  title 'The Arista perimeter router must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.'
  desc 'Many of the known attacks in stateless autoconfiguration are defined in RFC 3756 were present in IPv4 ARP attacks. To mitigate these vulnerabilities, links that have no hosts connected such as the interface connecting to external gateways must be configured to suppress router advertisements.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone. 

Review the Arista router configuration to verify Router Advertisements are suppressed on all external IPv6-enabled interfaces.

<Example configuration for VLAN 200>
interface vlan 200
 ipv6 nd ra disabled all

If the Arista router is not configured to suppress Router Advertisements on all external IPv6-enabled interfaces, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone. 

Configure the Arista router to suppress Router Advertisements on all external IPv6-enabled interfaces.

Configure the Arista router to suppress RAs on all IPv6 enabled interface as in the following example for VLAN 200:

router(config)#interface vlan 200
router(config-vl200)#ipv6 nd ra disabled all
router(config-vl200)#'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59735r882517_chk'
  tag severity: 'medium'
  tag gid: 'V-256059'
  tag rid: 'SV-256059r882519_rule'
  tag stig_id: 'ARST-RT-000800'
  tag gtitle: 'SRG-NET-000512-RTR-000014'
  tag fix_id: 'F-59678r882518_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-220146' do
  title 'The perimeter router must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.'
  desc 'Many of the known attacks in stateless autoconfiguration are defined in RFC 3756 were present in IPv4 ARP attacks. To mitigate these vulnerabilities, links that have no hosts connected such as the interface connecting to external gateways must be configured to suppress router advertisements.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify Router Advertisements are suppressed on all external IPv6-enabled interfaces.

If the router is not configured to suppress Router Advertisements on all external IPv6-enabled interfaces, this is a finding.'
  desc 'fix', 'Configure the router to suppress Router Advertisements on all external IPv6-enabled interfaces.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-21861r457765_chk'
  tag severity: 'medium'
  tag gid: 'V-220146'
  tag rid: 'SV-220146r604135_rule'
  tag stig_id: 'SRG-NET-000512-RTR-000014'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-21853r457766_fix'
  tag 'documentable'
  tag legacy: ['V-101087', 'SV-110191']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

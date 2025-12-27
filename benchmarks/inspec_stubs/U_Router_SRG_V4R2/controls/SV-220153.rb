control 'SV-220153' do
  title 'The perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type.'
  desc 'The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize, and hence could cause a Denial-of-Service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration and determine if filters are bound to the applicable interfaces to drop all inbound IPv6 packets containing an undefined option type value regardless of whether they appear in a Hop-by-Hop or Destination Option header. Undefined values are 0x02, 0x03, 0x06, 0x9 – 0xE, 0x10 – 0x22, 0x24, 0x25, 0x27 – 0x2F, and 0x31 – 0xFF.

If the router is not configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type, this is a finding.'
  desc 'fix', 'Configure the router to drop all inbound IPv6 packets containing an undefined option type value regardless of whether or not they appear in a Hop-by-Hop or Destination Option header.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-21868r457788_chk'
  tag severity: 'medium'
  tag gid: 'V-220153'
  tag rid: 'SV-220153r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000206'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-21861r539656_fix'
  tag 'documentable'
  tag legacy: ['V-101101', 'SV-110205']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end

control 'SV-220151' do
  title 'The perimeter router must be configured to drop IPv6 packets containing an extension header with the Endpoint Identification option.'
  desc 'The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize, and hence could cause a Denial-of-Service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large. This option type is associated with the Nimrod Routing system and has no defining RFC document.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router switch configuration and determine if filters are bound to the applicable interfaces to drop IPv6 packets containing an option type values of 0x8A (Endpoint Identification) regardless of whether it appears in a Hop-by-Hop or Destination Option header. 

Note: Because hop-by-hop and destination options have the same exact header format, they are combined under the dest-option-type keyword. According to Cisco, since Hop-by-Hop and Destination Option headers have non-overlapping types, dest-option-type to match either can be used. The Hop-by-Hop and Destination Option headers can be filtered via protocol 0 and 60 respectively. 

If the router is not configured to drop IPv6 packets containing an extension header with the Endpoint Identification option, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 packets containing an option type values of 0x8A (Endpoint Identification) regardless of whether it appears in a Hop-by-Hop or Destination Option header.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-21866r457782_chk'
  tag severity: 'medium'
  tag gid: 'V-220151'
  tag rid: 'SV-220151r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000204'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-21859r457783_fix'
  tag 'documentable'
  tag legacy: ['V-101097', 'SV-110201']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end

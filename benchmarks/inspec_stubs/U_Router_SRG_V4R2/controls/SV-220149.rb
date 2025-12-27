control 'SV-220149' do
  title 'The perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop header with invalid option type values.'
  desc 'These options are intended to be for the Destination Options header only. The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize and hence could cause a Denial-of-Service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to determine if filters are bound to the applicable interfaces to drop IPv6 packets containing a Hop-by-Hop header with option type values of 0x04 (Tunnel Encapsulation Limit), 0xC9 (Home Address Destination), or 0xC3 (NSAP Address). 

Note: Because hop-by-hop and destination options have the same exact header format, they are combined under the dest-option-type keyword. Since Hop-by-Hop and Destination Option headers have non-overlapping types, the dest-option-type to match either can be used. The Hop-by-Hop and Destination Option headers can be filtered via protocol 0 and 60 respectively. 

If the router is not configured to drop IPv6 packets containing a Hop-by-Hop header with invalid option type values, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 packets containing a Hop-by-Hop header with option type values of 0x04 (Tunnel Encapsulation Limit), 0xC9 (Home Address Destination), or 0xC3 (NSAP Address).'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-21864r457776_chk'
  tag severity: 'medium'
  tag gid: 'V-220149'
  tag rid: 'SV-220149r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000202'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-21857r457777_fix'
  tag 'documentable'
  tag legacy: ['V-101093', 'SV-110197']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end

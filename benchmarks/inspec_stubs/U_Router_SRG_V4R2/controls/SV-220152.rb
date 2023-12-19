control 'SV-220152' do
  title 'The perimeter router must be configured to drop IPv6 packets containing the NSAP address option within Destination Option header.'
  desc 'The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize, and hence could cause a Denial-of-Service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large. This option type from RFC 1888 (OSI NSAPs and IPv6) has been deprecated by RFC 4048.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration and determine if filters are bound to the applicable interfaces to drop IPv6 packets containing a Destination Option header with option type value of 0xC3 (NSAP address). 


Note: Because Hop-by-Hop and destination options have the same header format, they are combined under the dest-option-type keyword. According to Cisco, since Hop-by-Hop and Destination Option headers have non-overlapping types, dest-option-type to match either can be used. The Hop-by-Hop and Destination Option headers can be filtered via protocol 0 and 60 respectively. 

If the router is not configured to drop IPv6 packets containing the NSAP address option within Destination Option header, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 packets containing a Destination Option header with option type value of 0xC3 (NSAP address).'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-21867r457785_chk'
  tag severity: 'medium'
  tag gid: 'V-220152'
  tag rid: 'SV-220152r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000205'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-21860r457786_fix'
  tag 'documentable'
  tag legacy: ['V-101099', 'SV-110203']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end

control 'SV-220150' do
  title 'The perimeter router must be configured to drop IPv6 packets containing a Destination Option header with invalid option type values.'
  desc 'These options are intended to be for the Hop-by-Hop header only. The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize. Hence, this could cause a Denial-of-Service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration and determine if filters are bound to the external interfaces to drop IPv6 packets containing a Destination Option header with option type values of 0x05 (Router Alert) or 0xC2 (Jumbo Payload). 

Note: Because Hop-by-Hop and destination options have the same exact header format, they are combined under the dest-option-type keyword. According to Cisco, since Hop-by-Hop and Destination Option headers have non-overlapping types, dest-option-type to match either can be used. The Hop-by-Hop and Destination Option headers can be filtered via protocol 0 and 60 respectively. 

If the router is not configured to drop IPv6 packets containing a Destination Option header with invalid option type values, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 packets containing a Destination Option header with option type values of 0x05 (Router Alert) or 0xC2 (Jumbo Payload).'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-21865r457779_chk'
  tag severity: 'medium'
  tag gid: 'V-220150'
  tag rid: 'SV-220150r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000203'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-21858r457780_fix'
  tag 'documentable'
  tag legacy: ['V-101095', 'SV-110199']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end

control 'SV-220147' do
  title 'The perimeter router must be configured to drop IPv6 undetermined transport packets.'
  desc 'One of the fragmentation weaknesses known in IPv6 is the undetermined transport packet. This packet contains an undetermined protocol due to fragmentation. Depending on the length of the IPv6 extension header chain, the initial fragment may not contain the layer four port information of the packet.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to determine if it is configured to drop IPv6 undetermined transport packets.

If the router is not configured to drop IPv6 undetermined transport packets, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 undetermined transport packets.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-21862r457769_chk'
  tag severity: 'medium'
  tag gid: 'V-220147'
  tag rid: 'SV-220147r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000200'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-21855r457770_fix'
  tag 'documentable'
  tag legacy: ['V-101089', 'SV-110193']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end

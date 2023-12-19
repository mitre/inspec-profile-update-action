control 'SV-26075' do
  title 'The system must not apply reversed source routing to TCP responses.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'check', 'Determine if the system is configured to apply reverse source routing to TCP responses to source-routed packets.  If so, this is a finding.'
  desc 'fix', 'Configure the system to not apply reverse source routing to TCP responses to source-routed packets.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29250r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22412'
  tag rid: 'SV-26075r1_rule'
  tag stig_id: 'GEN003605'
  tag gtitle: 'GEN003605'
  tag fix_id: 'F-26269r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end

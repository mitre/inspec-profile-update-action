control 'SV-38799' do
  title 'The system must not apply reversed source routing to TCP responses.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'check', 'Determine if the system is configured to apply reverse source routing to TCP responses to source-routed packets.
# /usr/sbin/no -o nonlocsrcroute
If the value is not 0,  this is a finding.'
  desc 'fix', 'Configure the system to not apply reverse source routing to TCP responses to source-routed packets.   
# /usr/sbin/no -po nonlocsrcroute=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37255r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22412'
  tag rid: 'SV-38799r2_rule'
  tag stig_id: 'GEN003605'
  tag gtitle: 'GEN003605'
  tag fix_id: 'F-32495r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end

control 'SV-227798' do
  title 'The system must not apply reversed source routing to TCP responses.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces verify the system does not apply reversed source routing to TCP responses.

# ndd /dev/tcp tcp_rev_src_routes

If the result is not 0, this is a finding.'
  desc 'fix', 'Configure the system to not apply reversed source routing to TCP responses.
# ndd -set /dev/tcp tcp_rev_src_routes 0
Also add this command to a system startup script.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29960r489748_chk'
  tag severity: 'medium'
  tag gid: 'V-227798'
  tag rid: 'SV-227798r603266_rule'
  tag stig_id: 'GEN003605'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29948r489749_fix'
  tag 'documentable'
  tag legacy: ['SV-26626', 'V-22412']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

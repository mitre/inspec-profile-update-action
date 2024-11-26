control 'SV-227794' do
  title 'TCP backlog queue sizes must be set appropriately.'
  desc 'To provide some mitigation to TCP DoS attacks, the TCP backlog queue sizes must be set to at least 1280 or in accordance with product-specific guidelines.'
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces determine the network settings.

Procedure:
# ndd /dev/tcp tcp_conn_req_max_q0

If the returned value is not 1280 or greater, this is a finding.

Procedure:
# ndd /dev/tcp tcp_conn_req_max_q

If the returned value is not 1024, this is a finding.'
  desc 'fix', 'Procedure:
# ndd -set /dev/tcp tcp_conn_req_max_q0 1280
# ndd -set /dev/tcp tcp_conn_req_max_q 1024

Ensure these commands are also present in system startup scripts.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29956r489736_chk'
  tag severity: 'medium'
  tag gid: 'V-227794'
  tag rid: 'SV-227794r603266_rule'
  tag stig_id: 'GEN003601'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29944r489737_fix'
  tag 'documentable'
  tag legacy: ['V-23741', 'SV-28639']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

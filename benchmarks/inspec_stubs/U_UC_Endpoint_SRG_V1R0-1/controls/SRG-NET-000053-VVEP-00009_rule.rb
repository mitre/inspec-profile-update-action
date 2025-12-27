control 'SRG-NET-000053-VVEP-00009_rule' do
  title 'The Unified Communications Endpoint must be configured to limit the number of concurrent sessions to an organizationally defined number.'
  desc 'Unified Communications Endpoint management includes the ability to control the number of user sessions and limiting the number of allowed user sessions helps limit risk related to DoS attacks. Unified Communications Endpoint sessions occur peer-to-peer for media streams and client-server with session managers. For those endpoints that conference together multiple streams, the limit may be increased according to policy but a limit must still exist.'
  desc 'check', 'Verify the Unified Communications Endpoint is configured to limit the number of concurrent sessions to an organizationally defined number.

If the Unified Communications Endpoint is not configured to limit the number of concurrent sessions to the limit set by local policy, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to limit the number of concurrent sessions to the limit set by local policy.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000053-VVEP-00009_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000053-VVEP-00009'
  tag rid: 'SRG-NET-000053-VVEP-00009_rule'
  tag stig_id: 'SRG-NET-000053-VVEP-00009'
  tag gtitle: 'SRG-NET-000053-VVEP-00009'
  tag fix_id: 'F-SRG-NET-000053-VVEP-00009_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end

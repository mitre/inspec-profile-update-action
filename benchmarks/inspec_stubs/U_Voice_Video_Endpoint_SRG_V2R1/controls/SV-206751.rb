control 'SV-206751' do
  title 'The Voice Video Endpoint must limit the number of concurrent sessions to two (2) users.'
  desc 'Voice video endpoint management includes the ability to control the number of user sessions and limiting the number of allowed user sessions helps limit risk related to DoS attacks. Voice video endpoint sessions occur peer-to-peer for media streams and client-server with session managers. For those endpoints that conference together multiple streams, the limit may be increased according to policy but a limit must still exist.'
  desc 'check', 'Verify the Voice Video Endpoint limits the number of concurrent sessions to two users. Local policy may justify and increase the limit on concurrent user sessions to a number higher than two.

If the Voice Video Endpoint does not limit the number of concurrent sessions to two users, or the limit set by local policy, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to limit the number of concurrent sessions to two users or the limit set by local policy.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7007r363776_chk'
  tag severity: 'medium'
  tag gid: 'V-206751'
  tag rid: 'SV-206751r604140_rule'
  tag stig_id: 'SRG-NET-000053-VVEP-00009'
  tag gtitle: 'SRG-NET-000053'
  tag fix_id: 'F-7007r363777_fix'
  tag 'documentable'
  tag legacy: ['SV-81189', 'V-66699']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end

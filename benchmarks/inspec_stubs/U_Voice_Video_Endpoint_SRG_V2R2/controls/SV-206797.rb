control 'SV-206797' do
  title 'The Voice Video Endpoint auto-answer feature must be disabled.'
  desc 'A Voice Video Endpoint set to automatically answer a call with audio or video capabilities enabled risks transmitting information not intended for the caller. In the event a Voice Video Endpoint automatically answered a call during a classified meeting or discussion. Potentially sensitive or classified information could be transmitted. The auto-answer feature must not be activated by a user unless the feature is required to satisfy mission requirements.'
  desc 'check', 'Verify the Voice Video Endpoint auto-answer feature is disabled.

If the Voice Video Endpoint auto-answer feature is not disabled, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint auto-answer feature to be disabled.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7053r363914_chk'
  tag severity: 'medium'
  tag gid: 'V-206797'
  tag rid: 'SV-206797r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00050'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7053r363915_fix'
  tag 'documentable'
  tag legacy: ['V-66781', 'SV-81271']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

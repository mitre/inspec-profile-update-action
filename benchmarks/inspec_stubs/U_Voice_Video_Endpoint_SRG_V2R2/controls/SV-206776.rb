control 'SV-206776' do
  title 'The Voice Video Endpoint must provide an explicit indication of current participants in all Videoconference (VC)-based and IP-based online meetings and conferences.'
  desc 'Providing an explicit indication of current participants in teleconferences helps to prevent unauthorized individuals from participating in collaborative teleconference sessions without the explicit knowledge of other participants. Teleconferences allow groups of users to collaborate and exchange information. Without knowing who is in attendance, information could be compromised. This requirement excludes audio-only teleconferences using traditional telephony.

Network elements that provide a teleconference capability must provide a clear indication of who is attending the meeting, thus providing all attendees with the capability to clearly identify users who are in attendance.'
  desc 'check', 'Verify the Voice Video Endpoint provides an explicit indication of current participants in all VC-based and IP-based online meetings and conferences. This excludes audio-only teleconferences using traditional telephony.

If the Voice Video Endpoint does not provide an explicit indication of current participants in all VC-based and IP-based online meetings and conferences, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint provides an explicit indication of current participants in all VC-based and IP-based online meetings and conferences.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7032r363851_chk'
  tag severity: 'medium'
  tag gid: 'V-206776'
  tag rid: 'SV-206776r604140_rule'
  tag stig_id: 'SRG-NET-000353-VVEP-00042'
  tag gtitle: 'SRG-NET-000353'
  tag fix_id: 'F-7032r363852_fix'
  tag 'documentable'
  tag legacy: ['V-66765', 'SV-81255']
  tag cci: ['CCI-002453', 'CCI-000366']
  tag nist: ['SC-15 (4)', 'CM-6 b']
end

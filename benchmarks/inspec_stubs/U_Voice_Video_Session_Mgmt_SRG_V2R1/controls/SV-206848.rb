control 'SV-206848' do
  title 'The Voice Video Session Manager must provide an explicit indication of current participants in all videoconference-based and IP-based online meetings and conferences (excluding audio-only teleconferences using traditional telephony).'
  desc 'Providing an explicit indication of current participants in videoconferences helps to prevent unauthorized individuals from participating in collaborative videoconference sessions without the explicit knowledge of other participants. videoconferences allow groups of users to collaborate and exchange information. Without knowing who is in attendance, information could be compromised. For videoconferences with large numbers of people present, the identified participant may be listed as the room rather than by each individual attending.

Voice video session managers that provide a videoconference capability must provide a clear indication of who is attending the meeting, thus providing all attendees with the capability to clearly identify users who are in attendance.'
  desc 'check', 'Verify the Voice Video Session Manager provides an explicit indication of current participants in all videoconference-based and IP-based online meetings and conferences. This requirement does not apply to audio-only teleconferences using traditional telephony.

If the Voice Video Session Manager does not provide an explicit indication of current participants in all videoconference-based and IP-based online meetings and conferences, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to provide an explicit indication of current participants in all videoconference-based and IP-based online meetings and conferences, except audio-only teleconferences using traditional telephony.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7103r364733_chk'
  tag severity: 'medium'
  tag gid: 'V-206848'
  tag rid: 'SV-206848r508661_rule'
  tag stig_id: 'SRG-NET-000353-VVSM-00014'
  tag gtitle: 'SRG-NET-000353'
  tag fix_id: 'F-7103r364734_fix'
  tag 'documentable'
  tag legacy: ['SV-76617', 'V-62127']
  tag cci: ['CCI-002453', 'CCI-000366']
  tag nist: ['SC-15 (4)', 'CM-6 b']
end

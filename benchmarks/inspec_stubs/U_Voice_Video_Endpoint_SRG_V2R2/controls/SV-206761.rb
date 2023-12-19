control 'SV-206761' do
  title 'The Voice Video Endpoint used for videoconferencing must uniquely identify participating users.'
  desc "To assure accountability and prevent unauthenticated access, users must be identified to prevent potential misuse and compromise of the system. The Voice Video Endpoint must display the source of an incoming call and the participant's identity to aid the user in deciding whether to answer a call. The information potentially at risk is that which can be seen in the physical area of the Voice Video Endpoint or carried by the conference in which it is participating. 

This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', 'Verify the Voice Video Endpoint used for videoconferencing uniquely identifies participating users. Identification must be visible and displayed locally.

If the Voice Video Endpoint used for videoconferencing does not uniquely identify participating users, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint used for videoconferencing to uniquely identify participating users.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7017r363806_chk'
  tag severity: 'high'
  tag gid: 'V-206761'
  tag rid: 'SV-206761r604140_rule'
  tag stig_id: 'SRG-NET-000138-VVEP-00029'
  tag gtitle: 'SRG-NET-000138'
  tag fix_id: 'F-7017r363807_fix'
  tag 'documentable'
  tag legacy: ['V-66741', 'SV-81231']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

control 'SV-206795' do
  title 'The Voice Video Endpoint microphone must provide hardware mechanisms, such as push-to-talk (PTT) handset switches, to prevent pickup and transmission of sensitive or classified information over non-secure networks.'
  desc 'Microphones used with videoconferencing are designed to be extremely sensitive, designed to pick up audio from anywhere within a conference room. The microphones may pick up sidebar conversations with no relationship to the conference or call in progress. Speakerphones exhibit a similar vulnerability. This is especially at risk when unclassified conversations are conducted in classified spaces. Users or operators of videoconferencing systems must take care regarding what is being said and seen during a conference call and what sensitive information can be picked up by a camera or microphone. 

Voice Video Endpoints used in classified areas must use hardware mechanisms such as push-to-talk (PTT) to prevent conversations occurring in the area of the call from being heard over unclassified systems. This capability mitigates the risk to compromise sensitive or classified information not related to the conversation in progress. Speakers embedded in or connected to a Voice Video Endpoint may be turned up loud enough to be heard across a room or in the next workspace, risking compromise or sensitive or classified information.'
  desc 'check', 'If the unclassified Voice Video Endpoint is not deployed where sensitive or classified information is discussed, this check procedure is Not Applicable.

Verify the Voice Video Endpoint microphone provides hardware mechanisms, such as push-to-talk handset switches, to prevent pickup and transmission of sensitive or classified information over non-secure networks.

If the Voice Video Endpoint microphone does not provide hardware mechanisms, such as push-to-talk handset switches, to prevent pickup and transmission of sensitive or classified information over non-secure networks, this is a finding. If the Voice Video Endpoint microphone does provide hardware mechanisms but is not configured to use these features, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint microphone hardware mechanisms, such as push-to-talk handset switches, to prevent pickup and transmission of sensitive or classified information over non-secure networks.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7051r363908_chk'
  tag severity: 'medium'
  tag gid: 'V-206795'
  tag rid: 'SV-206795r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00048'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7051r363909_fix'
  tag 'documentable'
  tag legacy: ['SV-81267', 'V-66777']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-206796' do
  title 'The Voice Video Endpoint camera must provide hardware mechanisms, such as push-to-see (PTS) camera switches, to prevent pickup and transmission of sensitive or classified information over non-secure networks.'
  desc 'Cameras used with Voice Video Endpoints may reveal sensitive or classified information. This is especially at risk when unclassified conversations are conducted in classified spaces. Users or operators of videoconferencing systems must take care regarding what is being said and seen during a conference call and what sensitive information can be picked up by a camera or microphone. 

Voice Video Endpoints used in classified areas must use hardware mechanisms such as push-to-see (PTS) to prevent sensitive or classified information picked up by the camera in the area of the call from being transmitted over unclassified systems. This capability mitigates the risk to compromise sensitive or classified information not related to the conversation in progress.'
  desc 'check', 'If the unclassified Voice Video Endpoint is not deployed where sensitive or classified information is displayed or discussed, this check procedure is Not Applicable.

Verify the Voice Video Endpoint camera provides hardware mechanisms, such as push-to-see camera switches, to prevent pickup and transmission of sensitive or classified information over non-secure networks.

If the Voice Video Endpoint camera does not provide hardware mechanisms, such as push-to-see camera switches, to prevent pickup and transmission of sensitive or classified information over non-secure networks, this is a finding. If the Voice Video Endpoint camera does provide hardware mechanisms but is not configured to use these features, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint camera hardware mechanisms, such as push-to-see camera switches, to prevent pickup and transmission of sensitive or classified information over non-secure networks.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7052r363911_chk'
  tag severity: 'medium'
  tag gid: 'V-206796'
  tag rid: 'SV-206796r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00049'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7052r363912_fix'
  tag 'documentable'
  tag legacy: ['SV-81269', 'V-66779']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

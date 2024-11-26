control 'SV-206753' do
  title 'The Voice Video Endpoint must produce session (call detail) records containing what type of connection occurred.'
  desc 'Session records are commonly produced by session management and border elements. Many Voice Video Endpoints are not capable of providing session records and instead rely on session management and border elements. Voice video endpoints capable of producing session records provide supplemental confirmation of monitored events. Voice video endpoints that communicate beyond these defined environments must generate session records.

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records. Detailed records are typically produced by the session manager but can be augmented by non-telephone endpoint records.'
  desc 'check', 'If the Voice Video Endpoint relies exclusively on the Voice Video Session Manager for session records and does not have any capability for generating session records, this check procedure is Not Applicable.

Verify the Voice Video Endpoint produces session records containing what type of connection occurred. The record must include the session type (voice/direct, voice/conference, video/direct, video/conference, etc.), the specific protocols used for control and media traffic (SIP/SRTP, H.323, etc.), and the type of endpoint (mobile, telephone, codec, etc.).

If the Voice Video Endpoint does not produce session records containing what type of connection occurred, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to produce session records containing what type of connection occurred.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7009r363782_chk'
  tag severity: 'medium'
  tag gid: 'V-206753'
  tag rid: 'SV-206753r604140_rule'
  tag stig_id: 'SRG-NET-000074-VVEP-00022'
  tag gtitle: 'SRG-NET-000074'
  tag fix_id: 'F-7009r363783_fix'
  tag 'documentable'
  tag legacy: ['V-66727', 'SV-81217']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end

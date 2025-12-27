control 'SRG-NET-000074-VVEP-00022_rule' do
  title 'The Unified Communications Endpoint must be configured to produce session (call detail) records containing what type of connection occurred.'
  desc 'Session records are commonly produced by session management and border elements. Many Unified Communications Endpoints are not capable of providing session records and instead rely on session management and border elements. Unified Communications Endpoints capable of producing session records provide supplemental confirmation of monitored events. Unified Communications Endpoints that communicate beyond these defined environments must generate session records.

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records. Detailed records are typically produced by the session manager but can be augmented by nontelephone endpoint records.'
  desc 'check', 'Verify the Unified Communications Endpoint produces session records containing what type of connection occurred. The record must include the session type (voice/direct, voice/conference, video/direct, video/conference, etc.), the specific protocols used for control and media traffic (SIP/SRTP, H.323, etc.), and the type of endpoint (mobile, telephone, codec, etc.).

If the Unified Communications Endpoint does not produce session records containing what type of connection occurred, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to produce session records containing what type of connection occurred.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000074-VVEP-00022_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000074-VVEP-00022'
  tag rid: 'SRG-NET-000074-VVEP-00022_rule'
  tag stig_id: 'SRG-NET-000074-VVEP-00022'
  tag gtitle: 'SRG-NET-000074-VVEP-00022'
  tag fix_id: 'F-SRG-NET-000074-VVEP-00022_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end

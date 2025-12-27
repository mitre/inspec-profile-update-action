control 'SV-206755' do
  title 'The Voice Video Endpoint must produce session (call detail) records containing where the connection occurred.'
  desc 'Session records are commonly produced by session management and border elements. Many Voice Video Endpoints are not capable of providing session records and instead rely on session management and border elements. Voice video endpoints capable of producing session records provide supplemental confirmation of monitored events. Voice video endpoints that communicate beyond these defined environments must generate session records.

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records. Detailed records are typically produced by the session manager but can be augmented by non-telephone endpoint records.'
  desc 'check', 'If the Voice Video Endpoint relies exclusively on the Voice Video Session Manager for session records and does not have any capability for generating session records, this check procedure is Not Applicable.

Verify the Voice Video Endpoint produces session records containing where the connection occurred. The record must include IP addresses and port numbers.

If the Voice Video Endpoint does not produce session records containing where the connection occurred, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to produce session records containing where the connection occurred.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7011r363788_chk'
  tag severity: 'medium'
  tag gid: 'V-206755'
  tag rid: 'SV-206755r604140_rule'
  tag stig_id: 'SRG-NET-000076-VVEP-00024'
  tag gtitle: 'SRG-NET-000076'
  tag fix_id: 'F-7011r363789_fix'
  tag 'documentable'
  tag legacy: ['V-66731', 'SV-81221']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end

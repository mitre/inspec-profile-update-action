control 'SRG-NET-000076-VVEP-00024_rule' do
  title 'The Unified Communications Endpoint must be configured to produce session (call detail) records containing where the connection occurred.'
  desc 'Session records are commonly produced by session management and border elements. Many Unified Communications Endpoints are not capable of providing session records and instead rely on session management and border elements. Unified Communications Endpoints capable of producing session records provide supplemental confirmation of monitored events. Unified Communications Endpoints that communicate beyond these defined environments must generate session records.

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records. Detailed records are typically produced by the session manager but can be augmented by nontelephone endpoint records.'
  desc 'check', 'Verify the Unified Communications Endpoint produces session records containing where the connection occurred. The record must include IP addresses and port numbers.

If the Unified Communications Endpoint does not produce session records containing where the connection occurred, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to produce session records containing where the connection occurred.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000076-VVEP-00024_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000076-VVEP-00024'
  tag rid: 'SRG-NET-000076-VVEP-00024_rule'
  tag stig_id: 'SRG-NET-000076-VVEP-00024'
  tag gtitle: 'SRG-NET-000076-VVEP-00024'
  tag fix_id: 'F-SRG-NET-000076-VVEP-00024_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end

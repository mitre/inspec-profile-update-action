control 'SV-206818' do
  title 'The Voice Video Session Manager must produce session (call) records containing where (location) the connection originated.'
  desc 'Without the capability to generate session records, it is difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible. Session records are generated from several components within the Voice Video system (e.g., session manager, session border control, gateway, gatekeeper, or endpoints).

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records.'
  desc 'check', 'Verify the Voice Video Session Manager produces session records containing where (location) the connection originated.

If the Voice Video Session Manager does not produce session records containing where (location) the connection originated, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to produce session records containing where (location) the connection originated.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7073r364643_chk'
  tag severity: 'medium'
  tag gid: 'V-206818'
  tag rid: 'SV-206818r508661_rule'
  tag stig_id: 'SRG-NET-000076-VVSM-00030'
  tag gtitle: 'SRG-NET-000076'
  tag fix_id: 'F-7073r364644_fix'
  tag 'documentable'
  tag legacy: ['V-62067', 'SV-76557']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end

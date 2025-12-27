control 'SV-206815' do
  title 'The Voice Video Session Manager must produce session (call) records containing the type of session connection.'
  desc 'Without the capability to generate session records, it is difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible. Session records are generated from several components within the Voice Video system (e.g., session manager, session border control, gateway, gatekeeper, or endpoints).

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records.'
  desc 'check', 'Verify the Voice Video Session Manager produces session records containing the type of session connection.

If the Voice Video Session Manager does not produce session records containing the type of session connection, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to produce session records containing the type of session connection.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7070r364634_chk'
  tag severity: 'medium'
  tag gid: 'V-206815'
  tag rid: 'SV-206815r508661_rule'
  tag stig_id: 'SRG-NET-000074-VVSM-00029'
  tag gtitle: 'SRG-NET-000074'
  tag fix_id: 'F-7070r364635_fix'
  tag 'documentable'
  tag legacy: ['SV-76549', 'V-62059']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end

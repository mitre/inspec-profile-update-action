control 'SV-206821' do
  title 'The Voice Video Session Manager must produce session (call) records containing the identity of the users and identifiers associated with the session.'
  desc 'Without the capability to generate session records, it is difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible. Session records are generated from several components within the Voice Video system (e.g., session manager, session border control, gateway, gatekeeper, or endpoints).

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records.'
  desc 'check', 'Verify the Voice Video Session Manager produces session records containing the identity of the users and identifiers associated with the session. The identity of the users and identifiers of the call in this context would be the user ID or user name.

For Voice Video Session Managers that have the concept of a device rather than users and identifiers, this requirement is not applicable.

If the Voice Video Session Manager does not produce session records containing the identity of the users and identifiers associated with the session, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to produce session records containing the identity of the users and identifiers associated with the session.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7076r364652_chk'
  tag severity: 'medium'
  tag gid: 'V-206821'
  tag rid: 'SV-206821r508661_rule'
  tag stig_id: 'SRG-NET-000079-VVSM-00035'
  tag gtitle: 'SRG-NET-000079'
  tag fix_id: 'F-7076r364653_fix'
  tag 'documentable'
  tag legacy: ['V-62077', 'SV-76567']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

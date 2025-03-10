control 'SV-206820' do
  title 'The Voice Video Session Manager must produce session (call) records containing the outcome (status) of the connection.'
  desc 'Without the capability to generate session records, it is difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible. Session records are generated from several components within the Voice Video system (e.g., session manager, session border control, gateway, gatekeeper, or endpoints).

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records.'
  desc 'check', 'Verify the Voice Video Session Manager produces session records containing the outcome (status) of the connection. The outcome or status of a call includes call completed normally, busy endpoint, busy network, preempted, or other pertinent description.

If the Voice Video Session Manager does not produce session records containing the outcome (status) of the connection, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to produce session records containing the outcome (status) of the connection.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7075r364649_chk'
  tag severity: 'medium'
  tag gid: 'V-206820'
  tag rid: 'SV-206820r508661_rule'
  tag stig_id: 'SRG-NET-000078-VVSM-00033'
  tag gtitle: 'SRG-NET-000078'
  tag fix_id: 'F-7075r364650_fix'
  tag 'documentable'
  tag legacy: ['SV-76561', 'V-62071']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end

control 'SV-206817' do
  title 'The Voice Video Session Manager must produce session (call) records containing when (date and time) the connection was terminated.'
  desc 'Without the capability to generate session records, it is difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible. Session records are generated from several components within the Voice Video system (e.g., session manager, session border control, gateway, gatekeeper, or endpoints).

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records.'
  desc 'check', 'Verify the Voice Video Session Manager produces session records containing when (date and time) the connection was terminated.

If the Voice Video Session Manager does not produce session records containing when (date and time) the connection was terminated, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to produce session records containing when (date and time) the connection was terminated.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7072r364640_chk'
  tag severity: 'medium'
  tag gid: 'V-206817'
  tag rid: 'SV-206817r508661_rule'
  tag stig_id: 'SRG-NET-000075-VVSM-00032'
  tag gtitle: 'SRG-NET-000075'
  tag fix_id: 'F-7072r364641_fix'
  tag 'documentable'
  tag legacy: ['V-62063', 'SV-76553']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end

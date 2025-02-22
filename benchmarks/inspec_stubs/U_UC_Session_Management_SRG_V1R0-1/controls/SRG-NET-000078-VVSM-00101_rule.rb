control 'SRG-NET-000078-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must produce session (call) records containing the outcome (status) of the connection.'
  desc 'Without the capability to generate session records, it is difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible. Session records are generated from several components within the Voice Video system (e.g., session manager, session border control, gateway, gatekeeper, or endpoints).

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records.'
  desc 'check', 'Verify the Unified Communications Session Manager produces session records containing the outcome (status) of the connection. The outcome or status of a call includes call completed normally, busy endpoint, busy network, preempted, or other pertinent description.

If the Unified Communications Session Manager does not produce session records containing the outcome (status) of the connection, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to produce session records containing the outcome (status) of the connection.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000078-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000078-VVSM-00101'
  tag rid: 'SRG-NET-000078-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000078-VVSM-00101'
  tag gtitle: 'SRG-NET-000078-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000078-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end

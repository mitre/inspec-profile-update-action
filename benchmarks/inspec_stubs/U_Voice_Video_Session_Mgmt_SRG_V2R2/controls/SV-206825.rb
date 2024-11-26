control 'SV-206825' do
  title 'The Voice Video Session Manager must produce session (call) records for events determined to be significant and relevant by local policy.'
  desc 'Without the capability to generate session records, it is difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible. Session records are generated from several components within the Voice Video system (e.g., session manager, session border control, gateway, gatekeeper, or endpoints).

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records.'
  desc 'check', 'Verify the Voice Video Session Manager produces session records for events determined to be significant and relevant by local policy.

If the Voice Video Session Manager does not produce session records for events determined to be significant and relevant by local policy, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to produce session records for events determined to be significant and relevant by local policy.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7080r364664_chk'
  tag severity: 'medium'
  tag gid: 'V-206825'
  tag rid: 'SV-206825r508661_rule'
  tag stig_id: 'SRG-NET-000113-VVSM-00036'
  tag gtitle: 'SRG-NET-000113'
  tag fix_id: 'F-7080r364665_fix'
  tag 'documentable'
  tag legacy: ['V-62085', 'SV-76575']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end

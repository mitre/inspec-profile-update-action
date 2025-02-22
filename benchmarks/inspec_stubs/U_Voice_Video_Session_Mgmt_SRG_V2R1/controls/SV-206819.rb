control 'SV-206819' do
  title 'The Voice Video Session Manager must produce session (call) records containing the identity of the initiator of the call.'
  desc 'Without the capability to generate session records, it is difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible. Session records are generated from several components within the Voice Video system (e.g., session manager, session border control, gateway, gatekeeper, or endpoints).

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records.'
  desc 'check', 'Verify the Voice Video Session Manager produces session records containing the identity of the initiator of the call. The identity of the initiator of the call in this context would be the device ID or the address of the MAC or IP. For Voice Video Session Managers that have the concept of a user rather than device, this requirement is not applicable.

If the Voice Video Session Manager does not produce session records containing the identity of the initiator of the call, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to produce session records containing the identity of the initiator of the call.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7074r364646_chk'
  tag severity: 'medium'
  tag gid: 'V-206819'
  tag rid: 'SV-206819r508661_rule'
  tag stig_id: 'SRG-NET-000077-VVSM-00034'
  tag gtitle: 'SRG-NET-000077'
  tag fix_id: 'F-7074r364647_fix'
  tag 'documentable'
  tag legacy: ['V-62069', 'SV-76559']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end

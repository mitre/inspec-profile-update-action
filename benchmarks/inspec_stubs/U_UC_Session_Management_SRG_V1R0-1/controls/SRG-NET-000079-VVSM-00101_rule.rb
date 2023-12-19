control 'SRG-NET-000079-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must produce session (call) records containing the identity of the users and identifiers associated with the session.'
  desc 'Without the capability to generate session records, it is difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible. Session records are generated from several components within the Voice Video system (e.g., session manager, session border control, gateway, gatekeeper, or endpoints).

Session record content that may be necessary to satisfy this requirement includes, for example, type of connection, connection origination, time stamps, outcome, user identities, and user identifiers. Additionally, an adversary must not be able to modify or delete session records.'
  desc 'check', 'Verify the Unified Communications Session Manager produces session records containing the identity of the users and identifiers associated with the session. The identity of the users and identifiers of the call in this context would be the user ID or user name.

For Unified Communications Session Managers that have the concept of a device rather than users and identifiers, this requirement is not applicable.

If the Unified Communications Session Manager does not produce session records containing the identity of the users and identifiers associated with the session, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to produce session records containing the identity of the users and identifiers associated with the session.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000079-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000079-VVSM-00101'
  tag rid: 'SRG-NET-000079-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000079-VVSM-00101'
  tag gtitle: 'SRG-NET-000079-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000079-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

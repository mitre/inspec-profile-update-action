control 'SRG-NET-000079-VVEP-00026_rule' do
  title 'The Unified Communications Endpoint must be configured to produce session (call detail) records containing the identity of all users.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Audit records are commonly produced by session management and border elements. Many Unified Communications Endpoints are not capable of providing audit records and instead rely on session management and border elements. Unified Communications Endpoints capable of producing audit records provide supplemental confirmation of monitored events. Unified Communications Endpoints that communicate beyond these defined environments must generate audit records.'
  desc 'check', 'Verify the Unified Communications Endpoint produces session records containing the identity of all users on the call. 

If the Unified Communications Endpoint does not produce session records containing the identity of all users on the call, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to produce session records containing the identity of all users on the call.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000079-VVEP-00026_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000079-VVEP-00026'
  tag rid: 'SRG-NET-000079-VVEP-00026_rule'
  tag stig_id: 'SRG-NET-000079-VVEP-00026'
  tag gtitle: 'SRG-NET-000079-VVEP-00026'
  tag fix_id: 'F-SRG-NET-000079-VVEP-00026_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

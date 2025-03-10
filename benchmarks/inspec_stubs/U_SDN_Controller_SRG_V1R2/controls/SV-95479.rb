control 'SV-95479' do
  title 'The SDN controller must be configured to generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Review the SDN controller configuration to determine if the audit records will contain the identity of any individual or process associated with an event that is being logged. 

If the SDN controller is not configured to produce audit records containing the identity of any individual or process associated with an event being logged, this is a finding.'
  desc 'fix', 'Configure the SDN controller to the identity of any individual or process associated with an event in the log records.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80505r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80769'
  tag rid: 'SV-95479r1_rule'
  tag stig_id: 'SRG-NET-000079-SDN-000145'
  tag gtitle: 'SRG-NET-000079'
  tag fix_id: 'F-87623r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

control 'SV-202035' do
  title 'The network device must generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., administrators or processes acting on behalf of administrators) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'Determine if the network device generates audit records containing information that establishes the identity of any individual or process associated with the event.  This requirement may be verified by demonstration or validated test results. If the network device does not generate audit records containing information that establishes the identity of any individual or process associated with the event, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2161r381671_chk'
  tag severity: 'medium'
  tag gid: 'V-202035'
  tag rid: 'SV-202035r879568_rule'
  tag stig_id: 'SRG-APP-000100-NDM-000230'
  tag gtitle: 'SRG-APP-000100'
  tag fix_id: 'F-2162r381672_fix'
  tag 'documentable'
  tag legacy: ['SV-69389', 'V-55143']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

control 'SV-109159' do
  title 'The Central Log Server must generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'The Central Log Server must generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'fix', 'Configure the Central Log Server to produce audit records containing information to establish the identity of the individual or process associated with the event.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98905r1_chk'
  tag severity: 'low'
  tag gid: 'V-100055'
  tag rid: 'SV-109159r1_rule'
  tag stig_id: 'SRG-APP-000100-AU-000730'
  tag gtitle: 'SRG-APP-000100-AU-000730'
  tag fix_id: 'F-105739r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

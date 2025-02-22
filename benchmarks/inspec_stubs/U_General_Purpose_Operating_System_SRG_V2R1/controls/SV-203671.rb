control 'SV-203671' do
  title 'The operating system must produce audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish the identity of any individual or process associated with the event. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing information to establish the identity of any individual or process associated with the event.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3796r374900_chk'
  tag severity: 'medium'
  tag gid: 'V-203671'
  tag rid: 'SV-203671r379234_rule'
  tag stig_id: 'SRG-OS-000255-GPOS-00096'
  tag gtitle: 'SRG-OS-000255'
  tag fix_id: 'F-3796r374901_fix'
  tag 'documentable'
  tag legacy: ['V-57171', 'SV-71431']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

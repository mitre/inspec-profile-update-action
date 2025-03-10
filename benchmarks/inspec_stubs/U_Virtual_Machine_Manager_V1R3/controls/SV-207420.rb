control 'SV-207420' do
  title 'The VMM must produce audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Verify the VMM produces audit records containing information to establish the identity of any individual or process associated with the event.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to produce audit records containing information to establish the identity of any individual or process associated with the event.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7677r365670_chk'
  tag severity: 'medium'
  tag gid: 'V-207420'
  tag rid: 'SV-207420r379234_rule'
  tag stig_id: 'SRG-OS-000255-VMM-000890'
  tag gtitle: 'SRG-OS-000255'
  tag fix_id: 'F-7677r365671_fix'
  tag 'documentable'
  tag legacy: ['SV-71301', 'V-57041']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

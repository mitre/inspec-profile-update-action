control 'SV-71431' do
  title 'The operating system must produce audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish the identity of any individual or process associated with the event. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing information to establish the identity of any individual or process associated with the event.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57171'
  tag rid: 'SV-71431r1_rule'
  tag stig_id: 'SRG-OS-000255-GPOS-00096'
  tag gtitle: 'SRG-OS-000255-GPOS-00096'
  tag fix_id: 'F-62067r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

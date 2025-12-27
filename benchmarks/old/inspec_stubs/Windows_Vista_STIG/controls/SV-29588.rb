control 'SV-29588' do
  title 'Unapproved Users have access to Debug programs.'
  desc 'This is a Category 1 finding as it provides access to the kernel with complete access to sensitive and critical operating system components.'
  desc 'fix', 'Configure the system to remove any accounts from the "Debug programs" user right.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-18010'
  tag rid: 'SV-29588r1_rule'
  tag gtitle: 'User Right - Debug Programs'
  tag fix_id: 'F-18585r1_fix'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end

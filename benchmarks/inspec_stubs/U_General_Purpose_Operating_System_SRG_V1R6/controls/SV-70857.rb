control 'SV-70857' do
  title 'The operating system must prevent the use of dictionary words for passwords.'
  desc 'If the operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify the operating system prevents the use of dictionary words for passwords. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prevent the use of dictionary words for passwords.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57167r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56597'
  tag rid: 'SV-70857r1_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00225'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-61493r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

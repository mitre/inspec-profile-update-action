control 'SV-12476' do
  title 'The system must require passwords to contain no more than three consecutive repeating characters.'
  desc 'To enforce the use of complex passwords, the number of consecutive repeating characters is limited.  Passwords with excessive repeated characters may be more vulnerable to password-guessing attacks.'
  desc 'check', 'Verify the system requires passwords to contain no more than three consecutive repeating characters. If the system allows passwords to contain more than three consecutive repeating characters, this is a finding.'
  desc 'fix', 'Configure the system to require passwords to contain no more than three consecutive repeating characters.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7940r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11975'
  tag rid: 'SV-12476r2_rule'
  tag stig_id: 'GEN000680'
  tag gtitle: 'GEN000680'
  tag fix_id: 'F-24392r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

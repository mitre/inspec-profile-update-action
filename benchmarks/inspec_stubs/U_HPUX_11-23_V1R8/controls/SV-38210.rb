control 'SV-38210' do
  title 'The system must require passwords contain no more than three consecutive repeating characters.'
  desc 'To enforce the use of complex passwords, the number of consecutive repeating characters is limited.  Passwords with excessive repeated characters may be more vulnerable to password-guessing attacks.'
  desc 'check', 'HP-UX does not currently support enforcement of non-repeating characters; this is always considered a finding.'
  desc 'fix', 'Configure/modify the system policy to require passwords not contain more than three consecutive repeating characters.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36287r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11975'
  tag rid: 'SV-38210r1_rule'
  tag stig_id: 'GEN000680'
  tag gtitle: 'GEN000680'
  tag fix_id: 'F-31544r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

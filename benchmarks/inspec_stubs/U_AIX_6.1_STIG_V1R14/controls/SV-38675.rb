control 'SV-38675' do
  title 'The system must require passwords to contain no more than three consecutive repeating characters.'
  desc 'To enforce the use of complex passwords, the number of consecutive repeating characters is limited.  Passwords with excessive repeated characters may be more vulnerable to password-guessing attacks.'
  desc 'check', 'Check the maxrepeats setting.

Procedure:

# grep -i maxrepeats /etc/security/user
OR
# lsuser -a maxrepeats ALL

If the maxrepeats setting is greater than 3, this is a finding.'
  desc 'fix', 'Use the chsec command to set maxrepeats to 3.

# chsec -f /etc/security/user -s default -a maxrepeats=3

# chuser maxrepeats=3 < user id >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36902r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11975'
  tag rid: 'SV-38675r1_rule'
  tag stig_id: 'GEN000680'
  tag gtitle: 'GEN000680'
  tag fix_id: 'F-32056r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

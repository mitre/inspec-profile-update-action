control 'SV-38679' do
  title 'The system must prohibit the reuse of passwords within five iterations.'
  desc "If a user, or root, used the same password continuously or was allowed to change it back shortly after being forced to change it to something else, it would provide a potential intruder with the opportunity to keep guessing at one user's password until it was guessed correctly."
  desc 'check', 'Procedure:
#lsuser -a histsize ALL
If the returned histsize for any user is less than 5,  this is a finding.'
  desc 'fix', 'Use the chsec command to configure the system to prohibit the reuse of passwords within five iterations.

# chsec -f /etc/security/user -s default -a histsize=5
# chuser histsize=5 < user id >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36911r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4084'
  tag rid: 'SV-38679r1_rule'
  tag stig_id: 'GEN000800'
  tag gtitle: 'GEN000800'
  tag fix_id: 'F-32090r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end

control 'SV-4084' do
  title 'The system must prohibit the reuse of passwords within five iterations.'
  desc "If a user, or root, used the same password continuously or was allowed to change it back shortly after being forced to change it to something else, it would provide a potential intruder with the opportunity to keep guessing at one user's password until it was guessed correctly."
  desc 'check', 'Verify the system is configured to prohibit the reuse of passwords within five iterations.'
  desc 'fix', 'Configure the system to prohibit the reuse of passwords within five iterations.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-1670r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4084'
  tag rid: 'SV-4084r2_rule'
  tag stig_id: 'GEN000800'
  tag gtitle: 'GEN000800'
  tag fix_id: 'F-4017r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end

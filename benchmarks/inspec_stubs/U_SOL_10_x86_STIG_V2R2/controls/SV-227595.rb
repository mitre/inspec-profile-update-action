control 'SV-227595' do
  title 'The system must prohibit the reuse of passwords within five iterations.'
  desc "If a user, or root, used the same password continuously or was allowed to change it back shortly after being forced to change it to something else, it would provide a potential intruder with the opportunity to keep guessing at one user's password until it was guessed correctly."
  desc 'check', 'Check the HISTORY setting.
# grep HISTORY /etc/default/passwd
If HISTORY is not set to 5 or more, this is a finding.'
  desc 'fix', 'Edit /etc/default/passwd and set HISTORY to 5.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29757r488336_chk'
  tag severity: 'medium'
  tag gid: 'V-227595'
  tag rid: 'SV-227595r603266_rule'
  tag stig_id: 'GEN000800'
  tag gtitle: 'SRG-OS-000077'
  tag fix_id: 'F-29745r488337_fix'
  tag 'documentable'
  tag legacy: ['V-4084', 'SV-27132']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end

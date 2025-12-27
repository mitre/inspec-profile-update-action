control 'SV-45901' do
  title 'Files in /etc/news must be owned by root or news.'
  desc 'If critical system files are not owned by a privileged user, system integrity could be compromised.'
  desc 'check', 'Check the ownership of the files in "/etc/news".

Procedure:
# ls -al /etc/news

If any files are not owned by root or news, this is a finding.'
  desc 'fix', 'Change the ownership of the files in "/etc/news" to root or news.

Procedure:
# chown root /etc/news/*'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43211r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4277'
  tag rid: 'SV-45901r1_rule'
  tag stig_id: 'GEN006340'
  tag gtitle: 'GEN006340'
  tag fix_id: 'F-39281r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

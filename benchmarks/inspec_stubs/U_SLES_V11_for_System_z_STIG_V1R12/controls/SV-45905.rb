control 'SV-45905' do
  title 'The files in /etc/news must be group-owned by root or news.'
  desc 'If critical system files do not have a privileged group-owner, system integrity could be compromised.'
  desc 'check', 'Check "/etc/news" files group ownership:

Procedure:
# ls -al /etc/news

If "/etc/news" files are not group-owned by root or news, this is a finding.'
  desc 'fix', 'Change the group-owner of the files in "/etc/news" to root or news.

Procedure:
# chgrp root /etc/news/*'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43213r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4278'
  tag rid: 'SV-45905r1_rule'
  tag stig_id: 'GEN006360'
  tag gtitle: 'GEN006360'
  tag fix_id: 'F-39284r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

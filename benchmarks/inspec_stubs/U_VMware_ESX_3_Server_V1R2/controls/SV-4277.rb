control 'SV-4277' do
  title 'Files in /etc/news must be owned by root or news.'
  desc 'If critical system files are not owned by a privileged user, system integrity could be compromised.'
  desc 'check', 'Check the ownership of the files in /etc/news.

Procedure:
# ls -al /etc/news

If any files are not owned by root or news, this is a finding.'
  desc 'fix', 'Change the ownership of the files in /etc/news to root or news.

Procedure:
# chown root /etc/news/*'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28776r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4277'
  tag rid: 'SV-4277r2_rule'
  tag stig_id: 'GEN006340'
  tag gtitle: 'GEN006340'
  tag fix_id: 'F-4188r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

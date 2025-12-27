control 'SV-4278' do
  title 'The files in /etc/news must be group-owned by root or news.'
  desc 'If critical system files do not have a privileged group owner, system integrity could be compromised.'
  desc 'check', 'Check /etc/news files group ownership.

Procedure:
# ls -al /etc/news

If /etc/news files are not group-owned by root or news, this is a finding.'
  desc 'fix', 'Change the group owner of the files in /etc/news to root or news.

Procedure:
# chgrp root /etc/news/*'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2101r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4278'
  tag rid: 'SV-4278r2_rule'
  tag stig_id: 'GEN006360'
  tag gtitle: 'GEN006360'
  tag fix_id: 'F-4189r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-40837' do
  title 'The files in /etc/news must be group-owned by system or news.'
  desc 'If critical system files do not have a privileged group owner, system integrity could be compromised.'
  desc 'check', 'Check /etc/news files group ownership.

Procedure: 
# ls -al /etc/news 

If /etc/news files are not group-owned by system or news, this is a finding.'
  desc 'fix', 'Change the group owner of the files in /etc/news to system or news. 

Procedure:
# chgrp news /etc/news/*'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39549r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4278'
  tag rid: 'SV-40837r1_rule'
  tag stig_id: 'GEN006360'
  tag gtitle: 'GEN006360'
  tag fix_id: 'F-34681r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

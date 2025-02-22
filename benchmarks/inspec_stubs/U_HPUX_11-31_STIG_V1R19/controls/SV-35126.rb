control 'SV-35126' do
  title 'The files in /var/news must be group-owned by root or news.'
  desc 'If critical system files do not have a privileged group-owner, system integrity could be compromised.'
  desc 'check', 'Check news files group ownership.
# find /var/news -type f | xargs -n1 ls -lL

If news files are not group-owned by root or news, this is a finding.'
  desc 'fix', 'Change the group owner of the files in news to root or news.

# chgrp root <path>/news/*'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34984r3_chk'
  tag severity: 'medium'
  tag gid: 'V-4278'
  tag rid: 'SV-35126r1_rule'
  tag stig_id: 'GEN006360'
  tag gtitle: 'GEN006360'
  tag fix_id: 'F-30278r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

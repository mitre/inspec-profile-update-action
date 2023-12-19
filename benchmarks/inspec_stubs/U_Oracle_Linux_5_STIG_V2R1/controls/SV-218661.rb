control 'SV-218661' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20136r556181_chk'
  tag severity: 'medium'
  tag gid: 'V-218661'
  tag rid: 'SV-218661r603259_rule'
  tag stig_id: 'GEN006360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20134r556182_fix'
  tag 'documentable'
  tag legacy: ['V-4278', 'SV-63817']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end

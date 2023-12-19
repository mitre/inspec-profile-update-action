control 'SV-227947' do
  title 'The files in /etc/news must be group-owned by root.'
  desc 'If critical system files do not have a privileged group owner, system integrity could be compromised.'
  desc 'check', 'Check /etc/news directory and files group ownership.

Procedure:
# ls -al /etc/news

If the /etc/news directory and the files in it are not group-owned by root, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/news directory and the files in it to root.

Procedure:
# chgrp -R root /etc/news'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30109r490261_chk'
  tag severity: 'medium'
  tag gid: 'V-227947'
  tag rid: 'SV-227947r603266_rule'
  tag stig_id: 'GEN006360'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30097r490262_fix'
  tag 'documentable'
  tag legacy: ['V-4278', 'SV-40489']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-227946' do
  title 'Files in /etc/news must be owned by root.'
  desc 'If critical system files are not owned by a privileged user, system integrity could be compromised.'
  desc 'check', 'Check the ownership of the files in /etc/news.

Procedure:
# ls -al /etc/news

If the /etc/news directory or any files in it are not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the /etc/news directory and the files in it to root.

Procedure:
# chown -R root /etc/news'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30108r490258_chk'
  tag severity: 'medium'
  tag gid: 'V-227946'
  tag rid: 'SV-227946r603266_rule'
  tag stig_id: 'GEN006340'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30096r490259_fix'
  tag 'documentable'
  tag legacy: ['V-4277', 'SV-40487']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

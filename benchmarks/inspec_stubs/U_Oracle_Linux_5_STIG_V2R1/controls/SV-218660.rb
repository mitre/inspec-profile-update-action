control 'SV-218660' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20135r556178_chk'
  tag severity: 'medium'
  tag gid: 'V-218660'
  tag rid: 'SV-218660r603259_rule'
  tag stig_id: 'GEN006340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20133r556179_fix'
  tag 'documentable'
  tag legacy: ['V-4277', 'SV-63829']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

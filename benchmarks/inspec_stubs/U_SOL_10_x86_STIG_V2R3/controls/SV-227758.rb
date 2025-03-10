control 'SV-227758' do
  title 'The cron.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the cron.allow file is not set to root, bin, or sys, the possibility exists for an unauthorized user to view or to edit sensitive information.'
  desc 'check', '# ls -lL /etc/cron.d/cron.allow
If the cron.allow file is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', '# chown root /etc/cron.d/cron.allow'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29920r488858_chk'
  tag severity: 'medium'
  tag gid: 'V-227758'
  tag rid: 'SV-227758r603266_rule'
  tag stig_id: 'GEN003240'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29908r488859_fix'
  tag 'documentable'
  tag legacy: ['V-4361', 'SV-27366']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

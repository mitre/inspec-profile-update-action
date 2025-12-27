control 'SV-45644' do
  title 'The cron.deny file must be owned by root, bin, or sys.'
  desc 'Cron daemon control files restrict the scheduling of automated tasks and must be protected.'
  desc 'check', '# ls -lL /etc/cron.deny
If the cron.deny file is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', '# chown root /etc/cron.deny'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43010r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4430'
  tag rid: 'SV-45644r1_rule'
  tag stig_id: 'GEN003260'
  tag gtitle: 'GEN003260'
  tag fix_id: 'F-39042r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

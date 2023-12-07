control 'SV-27350' do
  title 'Cron logging must be implemented.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs.  It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  desc 'check', '# ls -lL /var/adm/cron/log
If this file does not exist or is older than the last cron job, this is a finding.'
  desc 'fix', 'Enable cron logging on the system.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28491r1_chk'
  tag severity: 'medium'
  tag gid: 'V-982'
  tag rid: 'SV-27350r1_rule'
  tag stig_id: 'GEN003160'
  tag gtitle: 'GEN003160'
  tag fix_id: 'F-1136r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

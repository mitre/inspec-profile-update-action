control 'SV-38549' do
  title 'Cron logging must be implemented.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs.  It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  desc 'check', '# ls -lL /var/adm/cron/log

If this file does not exist, or has a timestamp older than the last cron job, this is a finding.'
  desc 'fix', 'Enable cron/logging on the system via:

# /sbin/init.d/cron stop
# mv <current cron log> <to a new location and new name>
# /sbin/init.d/cron start
# more /var/adm/cron/log

Cron automatically handles its own logging function and (at least) the Start Time should be visible at the beginning of the new log file /var/adm/cron/log.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36455r1_chk'
  tag severity: 'medium'
  tag gid: 'V-982'
  tag rid: 'SV-38549r1_rule'
  tag stig_id: 'GEN003160'
  tag gtitle: 'GEN003160'
  tag fix_id: 'F-31794r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-1, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

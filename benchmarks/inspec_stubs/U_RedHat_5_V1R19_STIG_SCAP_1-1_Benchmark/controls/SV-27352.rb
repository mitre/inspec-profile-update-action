control 'SV-27352' do
  title 'Cron logging must be implemented.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs.  It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  desc 'fix', 'Edit /etc/syslog.conf or /etc/rsyslog.conf and setup cron logging'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-982'
  tag rid: 'SV-27352r2_rule'
  tag stig_id: 'GEN003160'
  tag gtitle: 'GEN003160'
  tag fix_id: 'F-31389r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

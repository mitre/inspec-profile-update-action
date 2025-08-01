control 'SV-37477' do
  title 'The cron log files must not have extended ACLs.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', "Check the permissions of the file.

Procedure:
Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file. Check the configured cron log file found in the cron entry in /etc/syslog.conf or /etc/rsyslog.conf(normally /var/log/cron).
# grep cron /etc/syslog.conf 
Or: 
# grep cron /etc/rsyslog.conf

# ls -lL /var/log/cron

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /var/log/cron'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36144r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22388'
  tag rid: 'SV-37477r2_rule'
  tag stig_id: 'GEN003190'
  tag gtitle: 'GEN003190'
  tag fix_id: 'F-31390r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

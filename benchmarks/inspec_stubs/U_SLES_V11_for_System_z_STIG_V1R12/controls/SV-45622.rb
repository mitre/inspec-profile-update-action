control 'SV-45622' do
  title 'The cron log files must not have extended ACLs.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', "Check the permissions of the file.

Procedure:
Check the configured cron log file found in the cron entry of the rsyslog configuration (normally /var/log/cron).
# grep cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf
# ls -lL /var/log/cron

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /var/log/cron'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42988r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22388'
  tag rid: 'SV-45622r1_rule'
  tag stig_id: 'GEN003190'
  tag gtitle: 'GEN003190'
  tag fix_id: 'F-39020r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

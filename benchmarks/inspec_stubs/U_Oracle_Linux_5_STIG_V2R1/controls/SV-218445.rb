control 'SV-218445' do
  title 'The cron log files must not have extended ACLs.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', "Check the permissions of the file.

Procedure:

Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.

Check the configured cron log file found in the cron entry in /etc/syslog.conf or /etc/rsyslog.conf(normally /var/log/cron).

# grep cron /etc/syslog.conf
 
Or:
 
# grep cron /etc/rsyslog.conf

# ls -lL /var/log/cron

If the permissions include a '+', the file has an extended ACL.

If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all /var/log/cron'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19920r562492_chk'
  tag severity: 'medium'
  tag gid: 'V-218445'
  tag rid: 'SV-218445r603259_rule'
  tag stig_id: 'GEN003190'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19918r562493_fix'
  tag 'documentable'
  tag legacy: ['V-22388', 'SV-64325']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

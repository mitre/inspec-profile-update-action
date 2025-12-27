control 'SV-44946' do
  title 'System log files must have mode 0640 or less permissive.'
  desc 'If the system log files are not protected, unauthorized users could change the logged data, eliminating its forensic value.'
  desc 'check', 'Check the mode of log files.

Procedure:
# ls -lL /var/log /var/log/syslog /var/adm

With the exception of /var/log/wtmp, if any of the log files have modes more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the system log file(s) to 0640 or less permissive.

Procedure:
# chmod 0640 /path/to/system-log-file

Note: Do not confuse system log files with audit logs.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42373r1_chk'
  tag severity: 'medium'
  tag gid: 'V-787'
  tag rid: 'SV-44946r1_rule'
  tag stig_id: 'GEN001260'
  tag gtitle: 'GEN001260'
  tag fix_id: 'F-38370r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

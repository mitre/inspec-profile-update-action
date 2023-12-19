control 'SV-37228' do
  title 'System log files must have mode 0640 or less permissive.'
  desc 'If the system log files are not protected, unauthorized users could change the logged data, eliminating its forensic value.'
  desc 'check', 'Check the mode of log files.

Procedure:
# find /var/log /var/log/syslog /var/adm -type f -perm -640 \\! -perm 640

With the exception of /var/log/wtmp, /var/log/Xorg.0.log, and /var/log/gdm/:0.log, if any of the log files have modes more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the system log file(s) to 0640 or less permissive.

Procedure:
# chmod 0640 /path/to/system-log-file

Note: Do not confuse system log files with audit logs.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35918r4_chk'
  tag severity: 'medium'
  tag gid: 'V-787'
  tag rid: 'SV-37228r3_rule'
  tag stig_id: 'GEN001260'
  tag gtitle: 'GEN001260'
  tag fix_id: 'F-31175r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

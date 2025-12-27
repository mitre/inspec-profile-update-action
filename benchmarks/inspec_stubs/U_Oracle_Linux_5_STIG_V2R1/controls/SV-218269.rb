control 'SV-218269' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19744r554144_chk'
  tag severity: 'medium'
  tag gid: 'V-218269'
  tag rid: 'SV-218269r603259_rule'
  tag stig_id: 'GEN001260'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-19742r554145_fix'
  tag 'documentable'
  tag legacy: ['V-787', 'SV-64487']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

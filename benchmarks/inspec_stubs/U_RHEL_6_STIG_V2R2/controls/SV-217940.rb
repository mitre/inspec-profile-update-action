control 'SV-217940' do
  title 'All rsyslog-generated log files must have mode 0600 or less permissive.'
  desc 'Log files can contain valuable information regarding system configuration. If the system log files are not protected, unauthorized users could change the logged data, eliminating their forensic value.'
  desc 'check', %q(The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's permissions: 

$ ls -l [LOGFILE]

The permissions should be 600, or more restrictive. Some log files referenced in /etc/rsyslog.conf may be created by other programs and may require exclusion from consideration.

If the permissions are not correct, this is a finding.)
  desc 'fix', %q(The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's permissions:

$ ls -l [LOGFILE]

If the permissions are not 600 or more restrictive, run the following command to correct this:

# chmod 0600 [LOGFILE])
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19421r376835_chk'
  tag severity: 'medium'
  tag gid: 'V-217940'
  tag rid: 'SV-217940r603264_rule'
  tag stig_id: 'RHEL-06-000135'
  tag gtitle: 'SRG-OS-000206'
  tag fix_id: 'F-19419r376836_fix'
  tag 'documentable'
  tag legacy: ['V-38623', 'SV-50424']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

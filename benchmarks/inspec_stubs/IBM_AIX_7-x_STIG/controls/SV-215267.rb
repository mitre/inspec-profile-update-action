control 'SV-215267' do
  title 'AIX log files must be owned by a system group.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify AIX or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Check the group of log files:

# ls -lL /var/log /var/log/syslog /var/adm 
/var/adm:
total 376
drw-r----- 2 root system 256 Jan 24 12:31 SRC
drwx------ 4 root system 256 Jan 24 07:28 config
-rw-r----- 1 root system 1081 Jan 24 09:05 dev_pkg.fail
-rw-r----- 1 root system 250 Jan 24 09:05 dev_pkg.success
-rw------- 1 root system 64 Jan 24 09:43 sulog
drwxr-xr-x 3 root system 256 Jan 24 12:28 sw
drwx------ 2 root system 256 Jan 24 08:06 wpars
-rw-r-----    1 adm adm  7517448 Apr 29 14:10 wtmp

/var/log:
total 8
drwxr-xr-x 2 root system 256 Jan 24 08:44 aso
-rw-r----- 1 root system 603 Jan 24 10:30 cache_mgt.dr.log

If any of the log files have group other than a system group, this is a finding.'
  desc 'fix', 'Change the group of the system log file(s) to a system group: 
# chgrp [system_group] /path/to/system-log-file'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16465r569440_chk'
  tag severity: 'medium'
  tag gid: 'V-215267'
  tag rid: 'SV-215267r508663_rule'
  tag stig_id: 'AIX7-00-002071'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-16463r569441_fix'
  tag 'documentable'
  tag legacy: ['SV-101553', 'V-91455']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

control 'SV-35275' do
  title 'System log files must have mode 0640 or less permissive.'
  desc 'If the system log files are not protected, unauthorized users could change the logged data, eliminating its forensic value.'
  desc 'check', 'Check the mode of log files.

# ls -lLR /var/log /var/log/syslog /var/adm /var/opt

Note that some of the above directories will contain more than just system log files. For example: /var/adm/sa, /var/adm/sw, etc. Any non-system log files contained within the above directories should be excluded from this requirement.

If any of the system log files have modes more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the system log files to 0640 or less permissive.

# chmod 0640 <path>/<system-log-file>

NOTE: Do not confuse system log files with audit logs.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36302r1_chk'
  tag severity: 'medium'
  tag gid: 'V-787'
  tag rid: 'SV-35275r1_rule'
  tag stig_id: 'GEN001260'
  tag gtitle: 'GEN001260'
  tag fix_id: 'F-31557r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

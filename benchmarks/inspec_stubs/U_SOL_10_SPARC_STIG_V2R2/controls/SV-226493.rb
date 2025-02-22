control 'SV-226493' do
  title 'System log files must have mode 0640 or less permissive.'
  desc 'If the system log files are not protected, unauthorized users could change the logged data, eliminating its forensic value.'
  desc 'check', 'Check the mode of log file hierarchies.

Procedure:
# ls -lLRa /var/log /var/adm

If any of the log files or their directories have modes more permissive than "0640", and these are not documented, this is a finding.'
  desc 'fix', 'Change the mode of the system log file(s) to 0640 or less permissive.

Procedure:
# chmod "0640" /path/to/system-log-file

NOTE: Do not confuse system log files with audit logs.   Any subsystems that require less stringent permissions must be documented.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28654r482864_chk'
  tag severity: 'medium'
  tag gid: 'V-226493'
  tag rid: 'SV-226493r603265_rule'
  tag stig_id: 'GEN001260'
  tag gtitle: 'SRG-OS-000206'
  tag fix_id: 'F-28642r482865_fix'
  tag 'documentable'
  tag legacy: ['V-787', 'SV-39832']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

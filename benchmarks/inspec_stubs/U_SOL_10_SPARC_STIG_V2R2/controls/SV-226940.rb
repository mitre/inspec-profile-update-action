control 'SV-226940' do
  title 'The SMTP service log file must not have an extended ACL.'
  desc 'If the SMTP service log file has an extended ACL, unauthorized users may be allowed to access or to modify the log file.'
  desc 'check', 'Examine /etc/syslog.conf and determine the log file(s) receiving logs for mail.crit, mail.debug, mail.*, or *.crit.
Check the permissions on these log files.
# ls -lL [log file]
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [log file]'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29102r485129_chk'
  tag severity: 'medium'
  tag gid: 'V-226940'
  tag rid: 'SV-226940r603265_rule'
  tag stig_id: 'GEN004510'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29090r485130_fix'
  tag 'documentable'
  tag legacy: ['V-22442', 'SV-26700']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

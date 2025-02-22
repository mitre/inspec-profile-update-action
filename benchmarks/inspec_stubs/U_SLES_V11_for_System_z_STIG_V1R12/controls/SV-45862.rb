control 'SV-45862' do
  title 'The SMTP service log file must not have an extended ACL.'
  desc 'If the SMTP service log file has an extended ACL, unauthorized users may be allowed to access or to modify the log file.'
  desc 'check', %q(# more /etc/rsyslog.conf
Examine /etc/rsyslog.conf and determine the log file(s) receiving logs for "mail.crit", "mail.debug", mail.*, or "*.crit".
Check the permissions on these log files.
# ls -lL <log file>

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'This fix is applicable to both Postfix and sendmail servers.
Remove the extended ACL from the file.
# setfacl --remove-all <log file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43157r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22442'
  tag rid: 'SV-45862r1_rule'
  tag stig_id: 'GEN004510'
  tag gtitle: 'GEN004510'
  tag fix_id: 'F-39243r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

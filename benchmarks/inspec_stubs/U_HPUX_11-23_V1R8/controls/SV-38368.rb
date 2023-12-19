control 'SV-38368' do
  title 'The SMTP service log file must not have an extended ACL.'
  desc 'If the SMTP service log file has an extended ACL, unauthorized users may be allowed to access or to modify the log file.'
  desc 'check', %q(Examine /etc/syslog.conf and determine the log file(s) receiving logs for mail.crit, mail.debug, mail.*, or *.crit. 
# cat /etc/syslog.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | \
egrep -i "mail.crit|mail.\*|\*.crit|mail.debug|\*.debug" | cut -f 2,2 -d " " | \
uniq | xargs -n1 ls -lL

Check the permissions on these log files.
# ls -lL <log file>

If the permissions include a "+", the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the optional ACL from the log file.
# chacl -z <log file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36568r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22442'
  tag rid: 'SV-38368r1_rule'
  tag stig_id: 'GEN004510'
  tag gtitle: 'GEN004510'
  tag fix_id: 'F-31936r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-35053' do
  title 'The SMTP service log file must be owned by root.'
  desc 'If the SMTP service log file is not owned by root, then unauthorized personnel may modify or delete the file to hide a system compromise.'
  desc 'check', %q(Locate any Sendmail log files by checking the syslog configuration file.
# cat /etc/syslog.conf | 	tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//'  | grep -v "^#" | \
egrep -i "mail.info|mail.debug|mail.\*|\*.info|\*.debug|\*.\*" | cut -f 2,2 -d " " | uniq | xargs -n1 ls -lL

Identify any log files configured for the "mail" service at any severity 
level, or those configured for all services. Check the ownership of these 
log files.

If any mail log file is not owned by root, this is a finding.)
  desc 'fix', 'Change the ownership of the sendmail log file.
# chown root <sendmail log file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36566r1_chk'
  tag severity: 'medium'
  tag gid: 'V-837'
  tag rid: 'SV-35053r1_rule'
  tag stig_id: 'GEN004480'
  tag gtitle: 'GEN004480'
  tag fix_id: 'F-31934r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

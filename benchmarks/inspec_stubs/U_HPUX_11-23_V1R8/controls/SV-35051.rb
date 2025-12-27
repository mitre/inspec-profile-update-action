control 'SV-35051' do
  title 'The system syslog service must log informational and more severe SMTP service messages.'
  desc 'If informational and more severe SMTP service messages are not logged, malicious activity on the system may go unnoticed.'
  desc 'check', %q(The syslog.conf file critical mail logging option line will typically appear as one of the following examples:

mail.crit 	/var/adm/messages
mail.*		/var/adm/messages
*.*		/var/adm/messages
*.crit		/var/adm/messages

Check the syslog configuration file for mail.crit logging configuration.

# cat /etc/syslog.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | egrep -i "mail.crit|mail.\*|\*.crit|\*.\*"

If syslog is not configured to log critical sendmail messages, this is a finding.)
  desc 'fix', 'Edit the syslog.conf file and add a configuration line specifying an appropriate destination for critical "mail" syslogs, for example:

mail.crit 	/var/adm/messages
mail.*	/var/adm/messages
*.*		/var/adm/messages
*.crit		/var/adm/messages'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36565r1_chk'
  tag severity: 'medium'
  tag gid: 'V-836'
  tag rid: 'SV-35051r1_rule'
  tag stig_id: 'GEN004460'
  tag gtitle: 'GEN004460'
  tag fix_id: 'F-31933r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1, ECAR-3, ECAR-1, ECAR-2'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

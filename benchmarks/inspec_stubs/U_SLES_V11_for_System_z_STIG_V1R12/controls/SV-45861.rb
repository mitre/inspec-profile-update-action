control 'SV-45861' do
  title 'The SMTP service log file must have mode 0644 or less permissive.'
  desc 'If the SMTP service log file is more permissive than 0644, unauthorized users may be allowed to change the log file.'
  desc 'check', 'Check the mode of the SMTP service log file.

Procedure:
# more /etc/rsyslog.conf
Check the configuration to determine which log files contain logs for mail.crit, mail.debug, or *.crit.
Procedure:
# ls -lL <file location>
The check procedure is the same for both sendmail and Postfix.
Identify any log files configured for the "mail" service (excluding mail.none) at any severity level and check the permissions 


If the log file permissions are greater than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the SMTP service log file.

Procedure:
The fix procedure is the same for both sendmail and Postfix.
# chmod 0644 <sendmail log file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43156r1_chk'
  tag severity: 'medium'
  tag gid: 'V-838'
  tag rid: 'SV-45861r1_rule'
  tag stig_id: 'GEN004500'
  tag gtitle: 'GEN004500'
  tag fix_id: 'F-39242r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

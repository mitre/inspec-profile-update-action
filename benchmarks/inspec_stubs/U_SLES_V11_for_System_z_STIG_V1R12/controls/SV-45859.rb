control 'SV-45859' do
  title 'The SMTP service log file must be owned by root.'
  desc 'If the SMTP service log file is not owned by root, then unauthorized personnel may modify or delete the file to hide a system compromise.'
  desc 'check', 'Locate any mail log files by checking the syslog configuration file.

Procedure:
# more /etc/rsyslog.conf
The check procedure is the same for both sendmail and Postfix.
Identify any log files configured for the "mail" service (excluding mail.none) at any severity level and check the ownership 

Procedure:
# ls -lL <file location>

If any mail log file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the sendmail log file.

Procedure:
The fix procedure is the same for both sendmail and Postfix.
# chown root <sendmail log file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43155r1_chk'
  tag severity: 'medium'
  tag gid: 'V-837'
  tag rid: 'SV-45859r1_rule'
  tag stig_id: 'GEN004480'
  tag gtitle: 'GEN004480'
  tag fix_id: 'F-39241r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

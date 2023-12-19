control 'SV-837' do
  title 'The SMTP service log file must be owned by root.'
  desc 'If the SMTP service log file is not owned by root, then unauthorized personnel may modify or delete the file to hide a system compromise.'
  desc 'check', 'Locate any mail log files by checking the syslog configuration file.

Procedure:
# more /etc/syslog.conf

Identify any log files configured for the mail service at any severity level, or those configured for all services. Check the ownership of these log files.

Procedure:
# ls -lL <file location>

If any mail log file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the Sendmail log file.
# chown root <sendmail log file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-8034r2_chk'
  tag severity: 'medium'
  tag gid: 'V-837'
  tag rid: 'SV-837r2_rule'
  tag stig_id: 'GEN004480'
  tag gtitle: 'GEN004480'
  tag fix_id: 'F-991r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-227845' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30007r489910_chk'
  tag severity: 'medium'
  tag gid: 'V-227845'
  tag rid: 'SV-227845r603266_rule'
  tag stig_id: 'GEN004480'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29995r489911_fix'
  tag 'documentable'
  tag legacy: ['V-837', 'SV-837']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

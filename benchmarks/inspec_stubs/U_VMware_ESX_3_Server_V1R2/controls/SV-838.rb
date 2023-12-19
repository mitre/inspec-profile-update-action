control 'SV-838' do
  title 'The SMTP service log file must have mode 0644 or less permissive.'
  desc 'If the SMTP service log file is more permissive than 0644, unauthorized users may be allowed to change the log file.'
  desc 'check', 'Check the mode of the SMTP service log file.

Procedure:
# more /etc/syslog.conf

Check the configuration to determine which log files contain logs for mail.crit, mail.debug, or *.crit.

Procedure:
# ls -lL <file location>

If the log file permissions are greater than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the SMTP service log file.

Procedure:
# chmod 0644 <sendmail log file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8035r2_chk'
  tag severity: 'medium'
  tag gid: 'V-838'
  tag rid: 'SV-838r2_rule'
  tag stig_id: 'GEN004500'
  tag gtitle: 'GEN004500'
  tag fix_id: 'F-992r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

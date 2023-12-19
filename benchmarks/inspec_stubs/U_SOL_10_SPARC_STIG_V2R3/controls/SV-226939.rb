control 'SV-226939' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29101r485126_chk'
  tag severity: 'medium'
  tag gid: 'V-226939'
  tag rid: 'SV-226939r854438_rule'
  tag stig_id: 'GEN004500'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29089r485127_fix'
  tag 'documentable'
  tag legacy: ['SV-838', 'V-838']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

control 'SV-215344' do
  title 'AIX sendmail logging must not be set to less than nine in the sendmail.cf file.'
  desc 'If Sendmail is not configured to log at level 9, system logs may not contain the information necessary for tracking unauthorized use of the sendmail service.'
  desc 'check', 'Check if "Sendmail" logging is set to level "9" by running command:

# grep "^O LogLevel" /etc/mail/sendmail.cf 
O LogLevel=9

If logging is set to less than "9", this is a finding.'
  desc 'fix', 'Edit /etc/mail/sendmail.cf file, locate the "O LogLevel" line, or add a new line if necessary, and change the log level to "9". The new LogLevel line should be:
O LogLevel=9'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16542r294483_chk'
  tag severity: 'medium'
  tag gid: 'V-215344'
  tag rid: 'SV-215344r508663_rule'
  tag stig_id: 'AIX7-00-003038'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16540r294484_fix'
  tag 'documentable'
  tag legacy: ['V-91635', 'SV-101733']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

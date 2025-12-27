control 'SV-37497' do
  title 'Sendmail logging must not be set to less than nine in the sendmail.cf file.'
  desc 'If Sendmail is not configured to log at level 9, system logs may not contain the information necessary for tracking unauthorized use of the sendmail service.'
  desc 'check', 'If the "sendmail" package is not installed, this is not applicable.

Check if sendmail logging is set to level nine:

Procedure:
for sendmail:
# grep "O L" /etc/mail/sendmail.cf

OR

# grep LogLevel /etc/mail/sendmail.cf

If logging is set to less than nine, this is a finding.

for Postfix:
This rule is not applicable to postfix which does not use "log levels" in the same fashion as sendmail.'
  desc 'fix', 'Edit the sendmail.cf file, locate the "O L" or "LogLevel" entry and change it to 9.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36154r3_chk'
  tag severity: 'low'
  tag gid: 'V-835'
  tag rid: 'SV-37497r2_rule'
  tag stig_id: 'GEN004440'
  tag gtitle: 'GEN004440'
  tag fix_id: 'F-31405r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

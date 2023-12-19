control 'SV-227843' do
  title 'Sendmail logging must not be set to less than nine in the sendmail.cf file.'
  desc 'If Sendmail is not configured to log at level 9, system logs may not contain the information necessary for tracking unauthorized use of the Sendmail service.'
  desc 'check', 'Check if Sendmail logging is set to level 9.

Procedure:
# grep "O L" /etc/mail/sendmail.cf

OR

# grep LogLevel /etc/mail/sendmail.cf

If logging is set to less than 9, this is a finding.'
  desc 'fix', 'Edit the sendmail.conf file, locate the "O L" or LogLevel entry and change it to 9.'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30005r489904_chk'
  tag severity: 'low'
  tag gid: 'V-227843'
  tag rid: 'SV-227843r603266_rule'
  tag stig_id: 'GEN004440'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29993r489905_fix'
  tag 'documentable'
  tag legacy: ['V-835', 'SV-835']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

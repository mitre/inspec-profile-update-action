control 'SV-99187' do
  title 'Sendmail logging must not be set to less than nine in the sendmail.cf file.'
  desc 'If Sendmail is not configured to log at level 9, system logs may not contain the information necessary for tracking unauthorized use of the sendmail service.'
  desc 'check', 'Check sendmail to determine if the logging level is set to level "9":

# grep "O L" /etc/sendmail.cf
OR
# grep LogLevel /etc/sendmail.cf

If logging is set to less than "9", this is a finding.'
  desc 'fix', 'Edit the "sendmail.cf" file, locate the "O L" or "LogLevel" entry, and change it to "9".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88229r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88537'
  tag rid: 'SV-99187r1_rule'
  tag stig_id: 'VROM-SL-000570'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95279r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

control 'SV-240439' do
  title 'Sendmail logging must not be set to less than nine in the sendmail.cf file.'
  desc 'If Sendmail is not configured to log at level 9, system logs may not contain the information necessary for tracking unauthorized use of the sendmail service.'
  desc 'check', 'Check sendmail to determine if the logging level is set to level nine:

# grep "O L" /etc/sendmail.cf
OR
# grep LogLevel /etc/sendmail.cf

If logging is set to less than nine, this is a finding.'
  desc 'fix', 'Edit the sendmail.cf file, locate the "O L" or "LogLevel" entry and change it to "9".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43672r671056_chk'
  tag severity: 'medium'
  tag gid: 'V-240439'
  tag rid: 'SV-240439r671058_rule'
  tag stig_id: 'VRAU-SL-000590'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43631r671057_fix'
  tag 'documentable'
  tag legacy: ['SV-100305', 'V-89655']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

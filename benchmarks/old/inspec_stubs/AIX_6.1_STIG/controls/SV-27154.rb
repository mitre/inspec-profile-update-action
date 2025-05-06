control 'SV-27154' do
  title 'The system must log successful and unsuccessful access to the root account.'
  desc 'If successful and unsuccessful logins and logouts are not monitored or recorded, access attempts cannot be tracked.  Without this logging, it may be impossible to track unauthorized access to the system.'
  desc 'check', 'Check the following log files to determine if access to the root account is being logged.  Try to su - and enter an incorrect password.

# more /var/adm/sulog

If root login accounts are not being logged, this is a finding.'
  desc 'fix', 'Troubleshoot the system logging configuration to provide for logging of root account login attempts.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28084r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11980'
  tag rid: 'SV-27154r1_rule'
  tag stig_id: 'GEN001060'
  tag gtitle: 'GEN001060'
  tag fix_id: 'F-11241r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

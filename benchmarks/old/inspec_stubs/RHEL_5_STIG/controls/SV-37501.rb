control 'SV-37501' do
  title 'The SMTP service log file must be owned by root.'
  desc 'If the SMTP service log file is not owned by root, then unauthorized personnel may modify or delete the file to hide a system compromise.'
  desc 'fix', 'Change the ownership of the sendmail log file.

Procedure:
The fix procedure is the same for both sendmail and Postfix.
# chown root <sendmail log file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-837'
  tag rid: 'SV-37501r3_rule'
  tag stig_id: 'GEN004480'
  tag gtitle: 'GEN004480'
  tag fix_id: 'F-31408r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

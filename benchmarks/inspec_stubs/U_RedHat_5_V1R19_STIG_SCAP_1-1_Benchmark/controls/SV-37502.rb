control 'SV-37502' do
  title 'The SMTP service log file must have mode 0644 or less permissive.'
  desc 'If the SMTP service log file is more permissive than 0644, unauthorized users may be allowed to change the log file.'
  desc 'fix', 'Change the mode of the SMTP service log file.

Procedure:
The fix procedure is the same for both sendmail and Postfix.
# chmod 0644 <sendmail log file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-838'
  tag rid: 'SV-37502r3_rule'
  tag stig_id: 'GEN004500'
  tag gtitle: 'GEN004500'
  tag fix_id: 'F-31410r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

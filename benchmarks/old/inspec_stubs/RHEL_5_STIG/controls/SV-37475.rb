control 'SV-37475' do
  title 'The alias file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification. If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect e-mail.'
  desc 'fix', 'Change the mode of the alias files as needed to function.

No higher than 0644.

Procedure:
for sendmail:
# chmod 0644 /etc/aliases /etc/aliases.db

for postfix (assuming the default postfix directory):
# chmod 0644 /etc/postfix/aliases /etc/postfix/aliases.db'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-832'
  tag rid: 'SV-37475r3_rule'
  tag stig_id: 'GEN004380'
  tag gtitle: 'GEN004380'
  tag fix_id: 'F-31387r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

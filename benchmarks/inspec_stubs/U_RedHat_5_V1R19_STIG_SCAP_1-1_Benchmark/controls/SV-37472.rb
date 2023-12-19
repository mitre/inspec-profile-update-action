control 'SV-37472' do
  title 'The alias file must be owned by root.'
  desc 'If the alias file is not owned by root, an unauthorized user may modify the file adding aliases to run malicious code or redirect e-mail.'
  desc 'fix', 'Change the owner of the /etc/aliases file to root.

Procedure:
for sendmail:
# chown root /etc/aliases
# chown root /etc/aliases.db

for postfix
# chown root /etc/postfix/aliases
# chown root /etc/postfix/aliases.db'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-831'
  tag rid: 'SV-37472r2_rule'
  tag stig_id: 'GEN004360'
  tag gtitle: 'GEN004360'
  tag fix_id: 'F-31384r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-45827' do
  title 'The alias file must be owned by root.'
  desc 'If the alias file is not owned by root, an unauthorized user may modify the file adding aliases to run malicious code or redirect e-mail.'
  desc 'check', 'Check the ownership of the alias files.

Procedure:
for sendmail:
# ls -lL /etc/aliases
# ls -lL /etc/aliases.db
If all the files are not owned by root, this is a finding.

for postfix:
Verify the location of the alias file.
# postconf alias_maps

This will return the location of the "aliases" file.

# ls -lL <postfix aliases file>
# ls -lL <postfix aliases.db file>
If all the files are not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/aliases file to root.

Procedure:
for sendmail:
# chown root /etc/aliases
# chown root /etc/aliases.db

for postfix
# chown root <postfix aliases file>
# chown root <postfix aliases.db file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43144r1_chk'
  tag severity: 'medium'
  tag gid: 'V-831'
  tag rid: 'SV-45827r1_rule'
  tag stig_id: 'GEN004360'
  tag gtitle: 'GEN004360'
  tag fix_id: 'F-39214r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

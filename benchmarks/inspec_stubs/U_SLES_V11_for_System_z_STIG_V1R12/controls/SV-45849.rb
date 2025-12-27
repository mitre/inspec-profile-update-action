control 'SV-45849' do
  title 'The alias file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification.  If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect e-mail.'
  desc 'check', 'Check the permissions of the alias file.

Procedure:
for sendmail:
# ls -lL /etc/aliases /etc/aliases.db
If an alias file has a mode more permissive than 0644, this is a finding.

for postfix:
Verify the location of the alias file.
# postconf alias_maps

This will return the location of the "aliases" file.

# ls -lL <postfix aliases file> <postfix aliases.db file>
If an alias file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the alias files as needed to function. No higher than 0644.
Procedure:
for sendmail:
# chmod 0644 /etc/aliases /etc/aliases.db

for postfix:
# chmod 0644 <postfix aliases file> <postfix aliases.db file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43147r1_chk'
  tag severity: 'medium'
  tag gid: 'V-832'
  tag rid: 'SV-45849r1_rule'
  tag stig_id: 'GEN004380'
  tag gtitle: 'GEN004380'
  tag fix_id: 'F-39233r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

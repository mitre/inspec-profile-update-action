control 'SV-45850' do
  title 'The alias file must not have an extended ACL.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification.  If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect e-mail.'
  desc 'check', %q(Check the permissions of the alias file.

Procedure:
for sendmail:
# ls -lL /etc/aliases /etc/aliases.db
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.

for postfix:
Verify the location of the alias file.
# postconf alias_maps

This will return the location of the "aliases" file.

# ls -lL <postfix aliases file> <postfix aliases.db file>
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended permissions from the alias files.
Procedure:
for sendmail:
# setfacl --remove-all /etc/aliases /etc/aliases.db

for postfix:
# setfacl --remove-all <postfix aliases file> <postfix aliases.db file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43148r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22439'
  tag rid: 'SV-45850r1_rule'
  tag stig_id: 'GEN004390'
  tag gtitle: 'GEN004390'
  tag fix_id: 'F-39234r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

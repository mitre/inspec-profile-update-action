control 'SV-37488' do
  title 'The alias file must not have an extended ACL.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification.  If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect e-mail.'
  desc 'check', %q(If the "sendmail" and "postfix" packages are not installed, this is not applicable.

Check the permissions of the alias file.

Procedure:
for sendmail:
# ls -lL /etc/aliases /etc/aliases.db
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.

for postfix:
Verify the location of the alias file.
# postconf alias maps

This will return the location of the "aliases" file, by default "/etc/postfix/aliases"

# ls -lL <postfix aliases file> <postfix aliases.db file>
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended permissions from the alias files.
Procedure:
for sendmail:
# setfacl --remove-all /etc/aliases /etc/aliases.db

for postfix (assuming the default postfix directory):
# setfacl --remove-all /etc/postfix/aliases /etc/postfix/aliases.db'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36146r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22439'
  tag rid: 'SV-37488r2_rule'
  tag stig_id: 'GEN004390'
  tag gtitle: 'GEN004390'
  tag fix_id: 'F-31396r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

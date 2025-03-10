control 'SV-227839' do
  title 'The alias file must not have an extended ACL.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification.  If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect email.'
  desc 'check', %q(Find the alias files on the system.

Procedure:
# egrep '^O(A| AliasFile)' /etc/mail/sendmail.cf

If the "alias file" is an NIS or LDAP map, this check is not applicable. The default location is /etc/mail/aliases.

Check the permissions of the alias file and the hashed version of it used by sendmail.

Procedure:
# ls -lL /etc/mail/aliases /etc/mail/aliases.db

If the permissions include a "+", the file has an extended ACL and this is a finding.)
  desc 'fix', 'Remove the extended ACL from the files.
# chmod A- /etc/mail/aliases /etc/mail/aliases.db'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30001r489892_chk'
  tag severity: 'medium'
  tag gid: 'V-227839'
  tag rid: 'SV-227839r603266_rule'
  tag stig_id: 'GEN004390'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29989r489893_fix'
  tag 'documentable'
  tag legacy: ['V-22439', 'SV-26687']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

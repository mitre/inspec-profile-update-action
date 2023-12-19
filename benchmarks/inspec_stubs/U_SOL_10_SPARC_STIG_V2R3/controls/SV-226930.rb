control 'SV-226930' do
  title 'The alias file must be owned by root.'
  desc 'If the alias file is not owned by root, an unauthorized user may modify the file to add aliases to run malicious code or redirect email.'
  desc 'check', %q(Note: If sendmail is not installed, this requirement is not applicable.

Find the alias file on the system.

Procedure:
# egrep '^O(A| AliasFile)' /etc/mail/sendmail.cf

If the "alias file" is an NIS or LDAP map, this check is not applicable.  The default location is /etc/mail/aliases.

Check the ownership of the alias file.

Procedure:
# ls -lL /etc/mail/aliases /etc/mail/aliases.db

If the alias files are not owned by root, this is a finding.)
  desc 'fix', 'Change the owner of the /etc/mail/aliases file (or equivalent, such as /usr/lib/aliases) to root.

Procedure:
# chown root /etc/mail/aliases'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29092r858546_chk'
  tag severity: 'medium'
  tag gid: 'V-226930'
  tag rid: 'SV-226930r858547_rule'
  tag stig_id: 'GEN004360'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29080r485097_fix'
  tag 'documentable'
  tag legacy: ['SV-40493', 'V-831']
  tag cci: ['CCI-002195']
  tag nist: ['AC-4 (8) (a)']
end

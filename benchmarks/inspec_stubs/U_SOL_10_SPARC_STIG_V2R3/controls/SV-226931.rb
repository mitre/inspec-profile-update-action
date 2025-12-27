control 'SV-226931' do
  title 'The alias file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification.  If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect email.'
  desc 'check', "Note: If sendmail is not installed, this requirement is not applicable.

Find the alias files on the system.

Procedure:
# egrep '^O(A| AliasFile)' /etc/mail/sendmail.cf

If the alias file is an NIS or LDAP map, this check is not applicable. The default location is /etc/mail/aliases.

Check the permissions of the alias file and the hashed version of it used by sendmail.

Procedure:
# ls -lL /etc/mail/aliases /etc/mail/aliases.db

If the alias files have a mode more permissive than 0644, this is a finding."
  desc 'fix', 'Change the mode of the /etc/mail/aliases files (or equivalent, such as /usr/lib/aliases) to 0644.

Procedure:
# chmod 0644 /etc/mail/aliases /etc/mail/aliases.db'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29093r858548_chk'
  tag severity: 'medium'
  tag gid: 'V-226931'
  tag rid: 'SV-226931r858549_rule'
  tag stig_id: 'GEN004380'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29081r485103_fix'
  tag 'documentable'
  tag legacy: ['SV-40651', 'V-832']
  tag cci: ['CCI-002195']
  tag nist: ['AC-4 (8) (a)']
end

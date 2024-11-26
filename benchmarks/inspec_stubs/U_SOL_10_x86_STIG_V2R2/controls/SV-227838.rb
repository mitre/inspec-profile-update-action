control 'SV-227838' do
  title 'The alias file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification.  If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect email.'
  desc 'check', "Find the alias files on the system.

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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30000r489889_chk'
  tag severity: 'medium'
  tag gid: 'V-227838'
  tag rid: 'SV-227838r603266_rule'
  tag stig_id: 'GEN004380'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29988r489890_fix'
  tag 'documentable'
  tag legacy: ['V-832', 'SV-40651']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

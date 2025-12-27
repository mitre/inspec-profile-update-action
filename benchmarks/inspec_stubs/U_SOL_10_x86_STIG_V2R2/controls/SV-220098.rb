control 'SV-220098' do
  title 'The aliases file must be group-owned by root, sys, smmsp, or bin.'
  desc 'If the alias file is not group-owned by root or a system group, an unauthorized user may modify the file to add aliases to run malicious code or redirect email.'
  desc 'check', %q(Find the alias files on the system.

Procedure:
# egrep '^O(A| AliasFile)' /etc/mail/sendmail.cf

If the "alias file" is an NIS or LDAP map, this check is not applicable. The default location is /etc/mail/aliases.

Check the group ownership of the alias file and the hashed version of it used by sendmail.

Procedure:
# ls -lL /etc/mail/aliases /etc/mail/aliases.db

If the file is not group-owned by root, sys, smmsp, or bin, this is a finding.)
  desc 'fix', 'Change the group owner of the /etc/mail/aliases files.

Procedure:
# chgrp bin /etc/mail/aliases 
# chgrp smmsp /etc/mail/aliases.db'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21807r489886_chk'
  tag severity: 'medium'
  tag gid: 'V-220098'
  tag rid: 'SV-220098r603266_rule'
  tag stig_id: 'GEN004370'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21806r489887_fix'
  tag 'documentable'
  tag legacy: ['V-22438', 'SV-37458']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

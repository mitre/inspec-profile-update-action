control 'SV-220045' do
  title 'The aliases file must be group-owned by root, sys, smmsp, or bin.'
  desc 'If the alias file is not group-owned by root or a system group, an unauthorized user may modify the file to add aliases to run malicious code or redirect email.'
  desc 'check', %q(Note: If sendmail is not installed, this requirement is not applicable.

Find the alias files on the system.

Procedure:
# egrep '^O(A| AliasFile)' /etc/mail/sendmail.cf

If the "alias file" is an NIS or LDAP map, this check is not applicable. The default location is /etc/mail/aliases.

Check the group ownership of the alias file and the hashed version of it used by sendmail.

Procedure:
# ls -lL /etc/mail/aliases /etc/mail/aliases.db

If the files are not group-owned by root, sys, smmsp, or bin, this is a finding.)
  desc 'fix', 'Change the group owner of the /etc/mail/aliases files.

Procedure:
# chgrp bin /etc/mail/aliases 
# chgrp smmsp /etc/mail/aliases.db'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21754r858544_chk'
  tag severity: 'medium'
  tag gid: 'V-220045'
  tag rid: 'SV-220045r858545_rule'
  tag stig_id: 'GEN004370'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21753r485100_fix'
  tag 'documentable'
  tag legacy: ['SV-37458', 'V-22438']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

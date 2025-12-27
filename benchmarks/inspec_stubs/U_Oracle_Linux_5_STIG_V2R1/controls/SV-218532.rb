control 'SV-218532' do
  title 'The aliases file must be group-owned by root, sys, bin, or system.'
  desc 'If the alias file is not group-owned by root or a system group, an unauthorized user may modify the file adding aliases to run malicious code or redirect e-mail.'
  desc 'check', 'If the "sendmail" and "postfix" packages are not installed, this is not applicable.

Check the group ownership of the alias files.

Procedure:
for sendmail:
# ls -lL /etc/aliases
If the files are not group-owned by root, this is a finding.

# ls -lL /etc/aliases.db
If the file is not group-owned by the same system group as sendmail, which is smmsp by default, this is a finding.

for postfix:
Verify the location of the alias file.
# postconf alias maps

This will return the location of the "aliases" file, by default "/etc/postfix/aliases"

# ls -lL <postfix aliases file>
If the files are not group-owned by root, this is a finding.

# ls -lL <postfix aliases.db file>
If the file is not group-owned by root, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/aliases file.

Procedure:
for sendmail:
# chgrp root /etc/aliases
# chgrp smmsp /etc/aliases.db

The aliases.db file must be owned by the same system group as sendmail, which is smmsp by default.

for postfix
# chgrp root /etc/postfix/aliases
# chgrp root /etc/postfix/aliases.db'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20007r562717_chk'
  tag severity: 'medium'
  tag gid: 'V-218532'
  tag rid: 'SV-218532r603259_rule'
  tag stig_id: 'GEN004370'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-20005r562718_fix'
  tag 'documentable'
  tag legacy: ['V-22438', 'SV-63613']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

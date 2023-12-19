control 'SV-37473' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36139r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22438'
  tag rid: 'SV-37473r2_rule'
  tag stig_id: 'GEN004370'
  tag gtitle: 'GEN004370'
  tag fix_id: 'F-31385r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-45848' do
  title 'The aliases file must be group-owned by root, sys, bin, or system.'
  desc 'If the alias file is not group-owned by root or a system group, an unauthorized user may modify the file adding aliases to run malicious code or redirect e-mail.'
  desc 'check', 'If the “sendmail” or “postfix” packages are not installed, this is not applicable.

Check the group ownership of the alias files.

Procedure:
for sendmail:
# ls -lL /etc/aliases
If the file is not group-owned by root, this is a finding.

# ls -lL /etc/aliases.db
If the file is not group-owned by root, this is a finding.

for postfix:
Verify the location of the alias file.
# postconf alias_maps

This will return the location of the "aliases" file, by default "/etc/aliases".

# ls -lL <postfix aliases file>
If the file is not group-owned by root, this is a finding.

# ls -lL <postfix aliases.db file>
If the file is not group-owned by root, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/aliases file.

Procedure:
for sendmail:
# chgrp root /etc/aliases
# chgrp root /etc/aliases.db


for postfix
# chgrp root <postfix aliases file>
# chgrp root <postfix aliases.db file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43146r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22438'
  tag rid: 'SV-45848r2_rule'
  tag stig_id: 'GEN004370'
  tag gtitle: 'GEN004370'
  tag fix_id: 'F-39232r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

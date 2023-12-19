control 'SV-218536' do
  title 'Files executed through a mail aliases file must be group-owned by root, bin, sys, or system, and must reside within a directory group-owned by root, bin, sys, or system.'
  desc 'If a file executed through a mail aliases file is not group-owned by root or a system group, it may be subject to unauthorized modification.  Unauthorized modification of files executed through aliases may allow unauthorized users to attain root privileges.'
  desc 'check', 'Examine the contents of the /etc/aliases file.

Procedure:
# more /etc/aliases
Examine the aliases file for any utilized directories or paths.

# ls -lL <file referenced from aliases>

Check the permissions for any paths referenced.
 
If the group owner of any file is not root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of the file referenced from /etc/aliases.

Procedure:
# chgrp root <file referenced from aliases>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20011r562729_chk'
  tag severity: 'medium'
  tag gid: 'V-218536'
  tag rid: 'SV-218536r603259_rule'
  tag stig_id: 'GEN004410'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20009r562730_fix'
  tag 'documentable'
  tag legacy: ['V-22440', 'SV-63719']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end

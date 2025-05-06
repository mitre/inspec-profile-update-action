control 'SV-227841' do
  title 'Files executed through a mail aliases file must be group-owned by root, bin, or sys, and must reside within a directory group-owned by root, bin, or sys.'
  desc 'If a file executed through a mail aliases file is not group-owned by root or a system group, it may be subject to unauthorized modification.  Unauthorized modification of files executed through aliases may allow unauthorized users to attain root privileges.'
  desc 'check', 'Examine the contents of the /etc/mail/aliases file.
For each file referenced, check the group ownership of the file.

Procedure:
# ls -lL <file referenced from aliases>

If the group owner of any file is not root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group ownership of the file referenced from /etc/mail/aliases.

Procedure:
# chgrp root <file referenced from aliases>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30003r489898_chk'
  tag severity: 'medium'
  tag gid: 'V-227841'
  tag rid: 'SV-227841r603266_rule'
  tag stig_id: 'GEN004410'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29991r489899_fix'
  tag 'documentable'
  tag legacy: ['V-22440', 'SV-39904']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

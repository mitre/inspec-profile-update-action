control 'SV-38373' do
  title 'Files executed through a mail aliases file must be group-owned by root, bin, sys, or other, and must reside within a directory group-owned by root, bin, sys, or other.'
  desc 'If a file executed through a mail aliases file is not group-owned by root or a system group, it may be subject to unauthorized modification.  Unauthorized modification of files executed through aliases may allow unauthorized users to attain root privileges.'
  desc 'check', 'Examine the contents of the /etc/mail/aliases file.
# cat /etc/mail/aliases | cut -f 2,2 -d ":" | grep "|"

For each file referenced, check the group ownership of the file.
# ls -lL <file referenced from aliases>

If the group owner of any file is not root, bin, sys or other, this is a finding.'
  desc 'fix', 'Change the group ownership of the file referenced from /etc/mail/aliases.
# chgrp root <file referenced from aliases>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36561r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22440'
  tag rid: 'SV-38373r1_rule'
  tag stig_id: 'GEN004410'
  tag gtitle: 'GEN004410'
  tag fix_id: 'F-31929r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

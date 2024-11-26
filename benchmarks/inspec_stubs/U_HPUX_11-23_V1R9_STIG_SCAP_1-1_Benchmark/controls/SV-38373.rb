control 'SV-38373' do
  title 'Files executed through a mail aliases file must be group-owned by root, bin, sys, or other, and must reside within a directory group-owned by root, bin, sys, or other.'
  desc 'If a file executed through a mail aliases file is not group-owned by root or a system group, it may be subject to unauthorized modification.  Unauthorized modification of files executed through aliases may allow unauthorized users to attain root privileges.'
  desc 'fix', 'Change the group ownership of the file referenced from /etc/mail/aliases.
# chgrp root <file referenced from aliases>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
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

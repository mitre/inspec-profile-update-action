control 'SV-35163' do
  title 'The aliases file must be group-owned by root, sys, bin, or other.'
  desc 'If the alias file is not group-owned by root, bin, sys or other, an unauthorized user may modify the file to add aliases to run malicious code or redirect e-mail.'
  desc 'fix', 'Change the group-owner of the /etc/mail/aliases file.
# chgrp root /etc/mail/aliases'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22438'
  tag rid: 'SV-35163r1_rule'
  tag stig_id: 'GEN004370'
  tag gtitle: 'GEN004370'
  tag fix_id: 'F-31924r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

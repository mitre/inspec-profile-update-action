control 'SV-40683' do
  title 'The aliases file must be group-owned by sys, bin, or system.'
  desc 'If the alias file is not group-owned by a system group, an unauthorized user may modify the file to add aliases to run malicious code or redirect e-mail.'
  desc 'check', 'Check the group ownership of the /etc/mail/aliases file.

Procedure:
# ls -lL /etc/mail/aliases

If the file is not group-owned by sys, bin, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/mail/aliases file.

Procedure:
# chgrp system /etc/mail/aliases'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39413r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22438'
  tag rid: 'SV-40683r1_rule'
  tag stig_id: 'GEN004370'
  tag gtitle: 'GEN004370'
  tag fix_id: 'F-34538r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

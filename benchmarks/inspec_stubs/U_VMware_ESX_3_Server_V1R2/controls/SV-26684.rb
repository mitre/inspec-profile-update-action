control 'SV-26684' do
  title 'The aliases file must be group-owned by root, sys, bin, or system.'
  desc 'If the alias file is not group-owned by root or a system group, an unauthorized user may modify the file to add aliases to run malicious code or redirect email.'
  desc 'check', 'Check the group ownership of the /etc/mail/aliases file.

Procedure:
# ls -lL /etc/mail/aliases

If the file is not group-owned by root, sys, bin, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/mail/aliases file.

Procedure:
# chgrp root /etc/mail/aliases'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27706r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22438'
  tag rid: 'SV-26684r1_rule'
  tag stig_id: 'GEN004370'
  tag gtitle: 'GEN004370'
  tag fix_id: 'F-23923r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

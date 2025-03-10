control 'SV-218465' do
  title 'The at directory must be group-owned by root, bin, sys, or cron.'
  desc 'If the group of the "at" directory is not root, bin, sys, or cron, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /var/spool/at

If the file is not group-owned by root, bin, sys, daemon or cron, this is a finding.'
  desc 'fix', 'Change the group ownership of the file to root, bin, sys, daemon or cron.

Procedure:
# chgrp <root or other system group> <"at" directory>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19940r562552_chk'
  tag severity: 'medium'
  tag gid: 'V-218465'
  tag rid: 'SV-218465r603259_rule'
  tag stig_id: 'GEN003430'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19938r562553_fix'
  tag 'documentable'
  tag legacy: ['V-22396', 'SV-64297']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

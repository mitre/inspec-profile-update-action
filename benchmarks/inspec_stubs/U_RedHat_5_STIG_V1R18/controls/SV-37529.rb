control 'SV-37529' do
  title 'The "at" directory must be group-owned by root, bin, sys, or cron.'
  desc 'If the group of the "at" directory is not root, bin, sys, or cron, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /var/spool/at

If the file is not group-owned by root, bin, sys, daemon or cron, this is a finding.'
  desc 'fix', 'Change the group ownership of the file to root, bin, sys, daemon or cron.

Procedure:
# chgrp <root or other system group> <"at" directory>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36188r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22396'
  tag rid: 'SV-37529r1_rule'
  tag stig_id: 'GEN003430'
  tag gtitle: 'GEN003430'
  tag fix_id: 'F-31443r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

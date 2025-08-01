control 'SV-218470' do
  title 'The at.deny file must be group-owned by root, bin, sys, or cron.'
  desc 'If the group owner of the at.deny file is not set to root, bin, sys, or cron, unauthorized users could be allowed to view or edit sensitive information contained within the file.  Unauthorized modification could result in Denial of Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /etc/at.deny

If the file is not group-owned by root, bin, sys, or cron, this is a finding.'
  desc 'fix', 'Change the group ownership of the at.deny file to root, sys, bin, or cron.

Procedure:
# chgrp root /etc/at.deny'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19945r562564_chk'
  tag severity: 'medium'
  tag gid: 'V-218470'
  tag rid: 'SV-218470r603259_rule'
  tag stig_id: 'GEN003490'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19943r562565_fix'
  tag 'documentable'
  tag legacy: ['V-22398', 'SV-64309']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

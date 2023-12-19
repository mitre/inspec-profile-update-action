control 'SV-218451' do
  title 'The cron.allow file must be group-owned by root, bin, sys, or cron.'
  desc 'If the group of the cron.allow is not set to root, bin, sys, or cron, the possibility exists for an unauthorized user to view or edit the list of users permitted to use cron.  Unauthorized modification of this file could cause Denial of Service to authorized cron users or provide unauthorized users with the ability to run cron jobs.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /etc/cron.allow

If the file exists and is not group-owned by root, bin, sys or cron, this is a finding.'
  desc 'fix', 'Change the group ownership of the file.

Procedure:
# chgrp root /etc/cron.allow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19926r562510_chk'
  tag severity: 'medium'
  tag gid: 'V-218451'
  tag rid: 'SV-218451r603259_rule'
  tag stig_id: 'GEN003250'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19924r562511_fix'
  tag 'documentable'
  tag legacy: ['V-22391', 'SV-64351']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

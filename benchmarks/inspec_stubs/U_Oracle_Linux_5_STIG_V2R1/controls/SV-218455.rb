control 'SV-218455' do
  title 'The cron.deny file must be group-owned by root, bin, or sys.'
  desc 'Cron daemon control files restrict the scheduling of automated tasks and must be protected.  Unauthorized modification of the cron.deny file could result in Denial of Service to authorized cron users or could provide unauthorized users with the ability to run cron jobs.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /etc/cron.deny

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group ownership of the file.
# chgrp root /etc/cron.deny'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19930r562522_chk'
  tag severity: 'medium'
  tag gid: 'V-218455'
  tag rid: 'SV-218455r603259_rule'
  tag stig_id: 'GEN003270'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19928r562523_fix'
  tag 'documentable'
  tag legacy: ['V-22394', 'SV-64365']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

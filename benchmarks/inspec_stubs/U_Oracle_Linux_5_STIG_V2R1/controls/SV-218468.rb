control 'SV-218468' do
  title 'The at.allow file must be group-owned by root, bin, sys, or cron.'
  desc 'If the group owner of the at.allow file is not set to root, bin, sys, or cron, unauthorized users could be allowed to view or edit the list of users permitted to run "at" jobs.  Unauthorized modification could result in Denial of Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /etc/at.allow

If the file is not group-owned by root, bin, sys, or cron, this is a finding.'
  desc 'fix', 'Change the group ownership of the file.

Procedure:
# chgrp root /etc/at.allow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19943r562558_chk'
  tag severity: 'medium'
  tag gid: 'V-218468'
  tag rid: 'SV-218468r603259_rule'
  tag stig_id: 'GEN003470'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19941r562559_fix'
  tag 'documentable'
  tag legacy: ['V-22397', 'SV-64413']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

control 'SV-26046' do
  title 'The cron.deny file must be group-owned by root, bin, sys, or cron.'
  desc 'Cron daemon control files restrict the scheduling of automated tasks and must be protected.  Unauthorized modification of the cron.deny file could result in Denial-of-Service to authorized cron users or could provide unauthorized users with the ability to run cron jobs.'
  desc 'check', "Determine the cron.deny file's group owner.

Procedure:
# ls -lL cron.deny

If the file is not group-owned by root, bin, sys, or cron, this is a finding."
  desc 'fix', 'Change the group owner of the cron.deny file to root, sys, bin, or cron.

Procedure:
# chown root /var/adm/cron/cron.deny'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29229r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22394'
  tag rid: 'SV-26046r1_rule'
  tag stig_id: 'GEN003270'
  tag gtitle: 'GEN003270'
  tag fix_id: 'F-26250r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

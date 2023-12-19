control 'SV-38251' do
  title 'Default system accounts (with the exception of root) must not be listed in the cron.allow file or must be included in the cron.deny file, if cron.allow does not exist.'
  desc 'To centralize the management of privileged account crontabs, of the default system accounts, only root may have a crontab.'
  desc 'check', 'Check the cron.allow and cron.deny files for the system.
# more /var/adm/cron/cron.allow
# more /var/adm/cron/cron.deny

If a default system account (such as bin, sys, adm, or other sys acct) is listed in the cron.allow file, or not listed in the cron.deny file if no cron.allow file exists, this is a finding.'
  desc 'fix', 'Remove default system accounts (such as bin, sys, adm, or others) from the cron.allow file if it exists, or add those accounts to the cron.deny file.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36469r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11995'
  tag rid: 'SV-38251r1_rule'
  tag stig_id: 'GEN003060'
  tag gtitle: 'GEN003060'
  tag fix_id: 'F-31812r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

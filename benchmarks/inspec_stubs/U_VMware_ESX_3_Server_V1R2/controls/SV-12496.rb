control 'SV-12496' do
  title 'Default system accounts (with the exception of root) must not be listed in the cron.allow file or must be included in the cron.deny file, if cron.allow does not exist.'
  desc 'To centralize the management of privileged account crontabs, of the default system accounts, only root may have a crontab.'
  desc 'check', 'Check the cron.allow and cron.deny files for the system.  If a default system account (such as bin, sys, adm, or others) is listed in the cron.allow file, or not listed in the cron.deny file if no cron.allow file exists, this is a finding.'
  desc 'fix', 'Remove default system accounts (such as bin, sys, adm, or others) from the cron.allow file if it exists, or add those accounts to the cron.deny file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7960r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11995'
  tag rid: 'SV-12496r2_rule'
  tag stig_id: 'GEN003060'
  tag gtitle: 'GEN003060'
  tag fix_id: 'F-11256r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

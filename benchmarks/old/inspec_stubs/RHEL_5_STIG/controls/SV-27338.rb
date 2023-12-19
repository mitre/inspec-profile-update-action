control 'SV-27338' do
  title 'Default system accounts (with the exception of root) must not be listed in the cron.allow file or must be included in the cron.deny file, if cron.allow does not exist.'
  desc 'To centralize the management of privileged account crontabs, of the default system accounts, only root may have a crontab.'
  desc 'fix', 'Remove default system accounts (such as bin, sys, adm, or others, traditionally UID less than 500) from the cron.allow file if it exists, or add those accounts to the cron.deny file.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-11995'
  tag rid: 'SV-27338r1_rule'
  tag stig_id: 'GEN003060'
  tag gtitle: 'GEN003060'
  tag fix_id: 'F-31374r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

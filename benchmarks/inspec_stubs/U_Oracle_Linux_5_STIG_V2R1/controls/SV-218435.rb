control 'SV-218435' do
  title 'Default system accounts (with the exception of root) must not be listed in the cron.allow file or must be included in the cron.deny file, if cron.allow does not exist.'
  desc 'To centralize the management of privileged account crontabs, of the default system accounts, only root may have a crontab.'
  desc 'check', 'Check the cron.allow and cron.deny files for the system.

# more /etc/cron.allow
# more /etc/cron.deny

If a default system account (such as bin, sys, adm, or others, traditionally UID less than 500) is listed in the cron.allow file, or not listed in the cron.deny file and if no cron.allow file exists, this is a finding.'
  desc 'fix', 'Remove default system accounts (such as bin, sys, adm, or others, traditionally UID less than 500) from the cron.allow file if it exists, or add those accounts to the cron.deny file.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19910r562465_chk'
  tag severity: 'medium'
  tag gid: 'V-218435'
  tag rid: 'SV-218435r603259_rule'
  tag stig_id: 'GEN003060'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19908r562466_fix'
  tag 'documentable'
  tag legacy: ['V-11995', 'SV-64395']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

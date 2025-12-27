control 'SV-227745' do
  title 'Default system accounts (with the exception of root) must not be listed in the cron.allow file or must be included in the cron.deny file, if cron.allow does not exist.'
  desc 'To centralize the management of privileged account crontabs, of the default system accounts, only root may have a crontab.'
  desc 'check', 'Check the cron.allow and cron.deny files for the system.
# more /etc/cron.d/cron.allow
# more /etc/cron.d/cron.deny
If a default system account (such as bin, sys, adm, or others) is listed in the cron.allow file, or not listed in the cron.deny file if no cron.allow file exists, this is a finding.'
  desc 'fix', 'Remove default system accounts (such as bin, sys, adm, or others) from the cron.allow file if it exists, or add those accounts to the cron.deny file.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29907r488819_chk'
  tag severity: 'medium'
  tag gid: 'V-227745'
  tag rid: 'SV-227745r603266_rule'
  tag stig_id: 'GEN003060'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29895r488820_fix'
  tag 'documentable'
  tag legacy: ['V-11995', 'SV-27335']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

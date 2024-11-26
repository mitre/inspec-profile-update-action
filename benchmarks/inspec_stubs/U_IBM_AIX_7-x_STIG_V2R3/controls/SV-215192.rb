control 'SV-215192' do
  title 'AIX default system accounts (with the exception of root) must not be listed in the cron.allow file or must be included in the cron.deny file, if cron.allow does not exist.'
  desc 'To centralize the management of privileged account crontabs, of the default system accounts, only root may have a crontab.'
  desc 'check', 'Check the "cron.allow" and "cron.deny" files for the system using commands:
# more /var/adm/cron/cron.allow 
# more /var/adm/cron/cron.deny 

If the "cron.allow" file exists and is empty, this is a finding.

If a default system account (such as bin, sys, adm, or lpd) is listed in the "cron.allow" file, or not listed in the "cron.deny" file, this is a finding.'
  desc 'fix', 'Remove default system accounts (such as bin, sys, adm, or lpd) from the "cron.allow" file, or add those accounts to the "cron.deny" file.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16390r294027_chk'
  tag severity: 'medium'
  tag gid: 'V-215192'
  tag rid: 'SV-215192r508663_rule'
  tag stig_id: 'AIX7-00-001033'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16388r294028_fix'
  tag 'documentable'
  tag legacy: ['SV-101707', 'V-91609']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

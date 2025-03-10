control 'SV-218442' do
  title 'Cron and crontab directories must be group-owned by root, sys, bin or cron.'
  desc "To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  Failure to give group-ownership of cron or crontab directories to a system group provides the designated group and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group owner of cron and crontab directories.

Procedure:
# ls -ld /var/spool/cron

# ls -ld /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -ld /etc/cron*|grep -v deny


If a directory is not group-owned by root, sys, bin, or cron, this is a finding.'
  desc 'fix', 'Change the group owner of cron and crontab directories.

# chgrp root <crontab directory>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19917r562486_chk'
  tag severity: 'medium'
  tag gid: 'V-218442'
  tag rid: 'SV-218442r603259_rule'
  tag stig_id: 'GEN003140'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19915r562487_fix'
  tag 'documentable'
  tag legacy: ['V-981', 'SV-64305']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

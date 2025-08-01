control 'SV-218434' do
  title 'Crontab files must be group-owned by root, cron, or the crontab creators primary group.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', "Check the group ownership of the crontab files.
Procedure:

# ls -lL /var/spool/cron

# ls -lL /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -lL /etc/cron*|grep -v deny

If the group owner is not root or the crontab owner's primary group, this is a finding."
  desc 'fix', "Change the group owner of the crontab file to root, cron, or the crontab's primary group.

Procedure:
# chgrp root [crontab file]"
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19909r562462_chk'
  tag severity: 'medium'
  tag gid: 'V-218434'
  tag rid: 'SV-218434r603259_rule'
  tag stig_id: 'GEN003050'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19907r562463_fix'
  tag 'documentable'
  tag legacy: ['V-22385', 'SV-64399']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

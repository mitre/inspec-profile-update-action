control 'SV-218440' do
  title 'Cron and crontab directories must not have extended ACLs.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  ACLs on cron and crontab directories may provide unauthorized access to these directories.  Unauthorized modifications to these directories or their contents may result in the addition of unauthorized cron jobs or deny service to authorized cron jobs.'
  desc 'check', "Check the permissions of the crontab directories.

Procedure:
# ls -ld /var/spool/cron

# ls -ld /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -ld /etc/cron*|grep -v deny

If the permissions include a '+' the directory has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the directory.

# setfacl --remove-all <crontab directory>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19915r562480_chk'
  tag severity: 'medium'
  tag gid: 'V-218440'
  tag rid: 'SV-218440r603259_rule'
  tag stig_id: 'GEN003110'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19913r562481_fix'
  tag 'documentable'
  tag legacy: ['V-22387', 'SV-64367']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

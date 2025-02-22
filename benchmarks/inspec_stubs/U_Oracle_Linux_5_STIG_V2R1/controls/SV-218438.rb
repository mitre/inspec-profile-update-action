control 'SV-218438' do
  title 'Crontab files must not have extended ACLs.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  ACLs on crontab files may provide unauthorized access to the files.'
  desc 'check', "Check the permissions of the crontab files.
Procedure:

# ls -lL /var/spool/cron

# ls -lL /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -lL /etc/cron*|grep -v deny

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [crontab file]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19913r562474_chk'
  tag severity: 'medium'
  tag gid: 'V-218438'
  tag rid: 'SV-218438r603259_rule'
  tag stig_id: 'GEN003090'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19911r562475_fix'
  tag 'documentable'
  tag legacy: ['V-22386', 'SV-64381']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

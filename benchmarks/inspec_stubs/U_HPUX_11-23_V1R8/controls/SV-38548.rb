control 'SV-38548' do
  title 'Cron and crontab directories must be group-owned by root, sys, bin or other.'
  desc "To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  Failure to give group-ownership of cron or crontab directories to a system group provides the designated group and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group owner of the crontab directories.
# ls -lLd /var/spool/cron/crontabs

If the directory is not group-owned by root, sys, bin or other,  this is a finding.'
  desc 'fix', 'Change the group owner of the crontab directories to root, sys, bin or other.

# chown root /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36454r1_chk'
  tag severity: 'medium'
  tag gid: 'V-981'
  tag rid: 'SV-38548r1_rule'
  tag stig_id: 'GEN003140'
  tag gtitle: 'GEN003140'
  tag fix_id: 'F-31793r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

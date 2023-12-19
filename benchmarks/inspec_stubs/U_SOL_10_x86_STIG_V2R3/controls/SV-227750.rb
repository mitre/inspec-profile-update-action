control 'SV-227750' do
  title 'Cron and crontab directories must be owned by root or bin.'
  desc "Incorrect ownership of the cron or crontab directories could permit unauthorized users the ability to alter cron jobs and run automated jobs as privileged users.  Failure to give ownership of cron or crontab directories to root or to bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the owner of the crontab directory.
# ls -ld /var/spool/cron/crontabs
If the owner of the crontab directory is not root or bin, this is a finding.'
  desc 'fix', 'Change the owner of the crontab directory.
# chown root /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29912r488834_chk'
  tag severity: 'medium'
  tag gid: 'V-227750'
  tag rid: 'SV-227750r603266_rule'
  tag stig_id: 'GEN003120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29900r488835_fix'
  tag 'documentable'
  tag legacy: ['V-980', 'SV-27345']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-245569' do
  title 'The AIX cron and crontab directories must be group-owned by cron.'
  desc "Incorrect group ownership of the cron or crontab directories could permit unauthorized users the ability to alter cron jobs and run automated jobs as privileged users. Failure to give ownership of cron or crontab directories to root or to bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group owner of the "crontab" directory using command:

# ls -ld /var/spool/cron/crontabs 
drwxrwx--- 2 bin cron 256 Jan 25 12:33 /var/spool/cron/crontabs

If the group owner of the "crontab" directory is not "cron", this is a finding.'
  desc 'fix', 'Change the group owner of the "crontab" directory:
# chgrp cron /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-48848r832904_chk'
  tag severity: 'medium'
  tag gid: 'V-245569'
  tag rid: 'SV-245569r832906_rule'
  tag stig_id: 'AIX7-00-002150'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48803r832905_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

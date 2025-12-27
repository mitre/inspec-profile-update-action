control 'SV-245567' do
  title 'The AIX /var/spool/cron/atjobs directory must be group-owned by cron.'
  desc "Unauthorized group ownership of the /var/spool/cron/atjobs directory could permit unauthorized users the ability to alter atjobs and run automated jobs as privileged users. Failure to set proper permissions of the /var/spool/cron/atjobs directory provides unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of the /var/spool/cron/atjobs directory using command:
# ls -ld /var/spool/cron/atjobs

The above command should yield the following output:
drw-r----- 1 bin cron 993 Mar 11 07:04 /var/spool/cron/atjobs

If the group owner of the "atjobs" directory is not "cron", this is a finding.'
  desc 'fix', 'Change the group ownership of the "atjobs" directory to cron using command: 
# chgrp cron /var/spool/cron/atjobs'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-48846r832901_chk'
  tag severity: 'medium'
  tag gid: 'V-245567'
  tag rid: 'SV-245567r832903_rule'
  tag stig_id: 'AIX7-00-002148'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48801r832902_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

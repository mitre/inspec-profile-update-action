control 'SV-226625' do
  title 'Cron and crontab directories must be group-owned by root, sys, or bin.'
  desc "To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  Failure to give group-ownership of cron or crontab directories to a system group provides the designated group and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group owner of the crontab directories.

Procedure:
# ls -ld /var/spool/cron/crontabs

If the directory is not group-owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the group owner of the crontab directories to root, sys, or bin.

Procedure:
# chgrp root /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28786r483287_chk'
  tag severity: 'medium'
  tag gid: 'V-226625'
  tag rid: 'SV-226625r603265_rule'
  tag stig_id: 'GEN003140'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28774r483288_fix'
  tag 'documentable'
  tag legacy: ['V-981', 'SV-27347']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

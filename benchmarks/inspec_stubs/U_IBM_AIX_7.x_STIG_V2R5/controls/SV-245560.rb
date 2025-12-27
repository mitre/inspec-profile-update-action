control 'SV-245560' do
  title 'AIX cron and crontab directories must have a mode of 0640 or less permissive.'
  desc "Incorrect permissions of the cron or crontab directories could permit unauthorized users the ability to alter cron jobs and run automated jobs as privileged users. Failure to set proper permissions of cron or crontab directories provides unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the mode of the "crontab" directory using command:

# ls -ld /var/spool/cron/crontabs 
drw-r----- 2 bin cron 256 Jan 25 12:33 /var/spool/cron/crontabs

If the file has a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Change the owner of the "crontab" directory:
# chmod 640 /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-48839r755119_chk'
  tag severity: 'medium'
  tag gid: 'V-245560'
  tag rid: 'SV-245560r755121_rule'
  tag stig_id: 'AIX7-00-002143'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48794r755120_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-215270' do
  title 'AIX cron and crontab directories must be owned by root or bin.'
  desc "Incorrect ownership of the cron or crontab directories could permit unauthorized users the ability to alter cron jobs and run automated jobs as privileged users. Failure to give ownership of cron or crontab directories to root or to bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the owner of the "crontab" directory using command:

# ls -ld /var/spool/cron/crontabs 
drwxrwx---    2 bin      cron            256 Jan 25 12:33 /var/spool/cron/crontabs

If the owner of the "crontab" directory is not "root" or "bin", this is a finding.'
  desc 'fix', 'Change the owner of the "crontab" directory:
# chown root /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16468r294261_chk'
  tag severity: 'medium'
  tag gid: 'V-215270'
  tag rid: 'SV-215270r508663_rule'
  tag stig_id: 'AIX7-00-002078'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16466r294262_fix'
  tag 'documentable'
  tag legacy: ['V-91595', 'SV-101693']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

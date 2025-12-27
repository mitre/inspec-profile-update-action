control 'SV-218441' do
  title 'Cron and crontab directories must be owned by root or bin.'
  desc "Incorrect ownership of the cron or crontab directories could permit unauthorized users the ability to alter cron jobs and run automated jobs as privileged users.  Failure to give ownership of cron or crontab directories to root or to bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the owner of the crontab directories.
Procedure:

# ls -ld /var/spool/cron

# ls -ld /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -ld /etc/cron*|grep -v deny


If the owner of any of the crontab directories is not root or bin, this is a finding.'
  desc 'fix', 'Change the mode of the crontab directories.

# chown root <crontab directory>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19916r562483_chk'
  tag severity: 'medium'
  tag gid: 'V-218441'
  tag rid: 'SV-218441r603259_rule'
  tag stig_id: 'GEN003120'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19914r562484_fix'
  tag 'documentable'
  tag legacy: ['V-980', 'SV-64293']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

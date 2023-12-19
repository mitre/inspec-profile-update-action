control 'SV-45568' do
  title 'Access to the cron utility must be controlled using the cron.allow and/or cron.deny file(s).'
  desc 'The cron facility allows users to execute recurring jobs on a regular and unattended basis.  The cron.allow file designates accounts allowed to enter and execute jobs using the cron facility.  If neither cron.allow nor cron.deny exists, then any account may use the cron facility.  This may open the facility up for abuse by system intruders and malicious users.'
  desc 'check', 'Check for the existence of the cron.allow and cron.deny files.
# ls -lL /etc/cron.allow
# ls -lL /etc/cron.deny
If neither file exists, this is a finding.'
  desc 'fix', 'Create /etc/cron.allow and/or /etc/cron.deny with appropriate content.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42919r1_chk'
  tag severity: 'medium'
  tag gid: 'V-974'
  tag rid: 'SV-45568r1_rule'
  tag stig_id: 'GEN002960'
  tag gtitle: 'GEN002960'
  tag fix_id: 'F-38965r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

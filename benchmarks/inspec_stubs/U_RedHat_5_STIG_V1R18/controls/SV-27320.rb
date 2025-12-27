control 'SV-27320' do
  title 'Access to the cron utility must be controlled using the cron.allow and/or cron.deny file(s).'
  desc 'The cron facility allows users to execute recurring jobs on a regular and unattended basis. The cron.allow file designates accounts allowed to enter and execute jobs using the cron facility.  If the cron.allow file is not present, users listed in the cron.deny file are not allowed to use the cron facility.  Improper configuration of cron may open the facility up for abuse by system intruders and malicious users.'
  desc 'check', 'This check is not applicable if only the root user is permitted to use cron.

Check for the existence of the cron.allow and cron.deny files.
# ls -lL /etc/cron.allow
# ls -lL /etc/cron.deny
If neither file exists, this is a finding.'
  desc 'fix', 'Create /etc/cron.allow and/or /etc/cron.deny with appropriate content and reboot the system to ensure no lingering cron jobs are processed.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-28457r2_chk'
  tag severity: 'medium'
  tag gid: 'V-974'
  tag rid: 'SV-27320r2_rule'
  tag stig_id: 'GEN002960'
  tag gtitle: 'GEN002960'
  tag fix_id: 'F-24560r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

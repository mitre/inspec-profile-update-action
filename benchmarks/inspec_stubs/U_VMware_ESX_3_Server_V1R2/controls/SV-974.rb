control 'SV-974' do
  title 'Access to the cron utility must be controlled using the cron.allow and/or cron.deny file(s).'
  desc 'The cron facility allows users to execute recurring jobs on a regular and unattended basis.  The cron.allow file designates accounts that are allowed to enter and execute jobs using the cron facility.  If neither cron.allow nor cron.deny exists, then any account may use the cron facility.  This may open the facility up for abuse by system intruders and malicious users.'
  desc 'check', 'Check for the existence of the cron.allow and cron.deny files.  If neither file exists, this is a finding.'
  desc 'fix', 'Create a cron.allow and/or cron.deny file(s) with appropriate content in the appropriate directory for the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-786r2_chk'
  tag severity: 'medium'
  tag gid: 'V-974'
  tag rid: 'SV-974r2_rule'
  tag stig_id: 'GEN002960'
  tag gtitle: 'GEN002960'
  tag fix_id: 'F-1128r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

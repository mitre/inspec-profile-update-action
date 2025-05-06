control 'SV-227738' do
  title 'Access to the cron utility must be controlled using the cron.allow and/or cron.deny file(s).'
  desc 'The cron facility allows users to execute recurring jobs on a regular and unattended basis.  The cron.allow file designates accounts allowed to enter and execute jobs using the cron facility.  If neither cron.allow nor cron.deny exists, then any account may use the cron facility.  This may open the facility up for abuse by system intruders and malicious users.'
  desc 'check', 'Check for the existence of the cron.allow and cron.deny files.
# ls -lL /etc/cron.d/cron.allow
# ls -lL /etc/cron.d/cron.deny
If neither file exists, this is a finding.'
  desc 'fix', 'Create /etc/cron.d/cron.allow and/or /etc/cron.d/cron.deny with appropriate content.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29900r488798_chk'
  tag severity: 'medium'
  tag gid: 'V-227738'
  tag rid: 'SV-227738r603266_rule'
  tag stig_id: 'GEN002960'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29888r488799_fix'
  tag 'documentable'
  tag legacy: ['V-974', 'SV-27317']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

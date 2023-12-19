control 'SV-227987' do
  title 'The system package management tool must not automatically obtain updates.'
  desc "System package management tools can obtain a list of updates and patches from a package repository and make this information available to the SA for review and action. Using a package repository outside of the organization's control, presents a risk that malicious packages could be introduced."
  desc 'check', 'Determine if the system package management tool is configured to automatically obtain updated packages using the cron or at utilities.

# grep smpatch /var/spool/cron/crontabs/* /var/spool/cron/atjobs/*

If smpatch is called with the add, update, or remove subcommands, this is a finding.'
  desc 'fix', 'Disable any cron or at jobs running smpatch.

# crontab -e < user running smpatch >
# atrm < id of at job running smpatch >'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30149r490420_chk'
  tag severity: 'low'
  tag gid: 'V-227987'
  tag rid: 'SV-227987r603266_rule'
  tag stig_id: 'GEN008820'
  tag gtitle: 'SRG-OS-000191'
  tag fix_id: 'F-30137r490421_fix'
  tag 'documentable'
  tag legacy: ['V-22589', 'SV-40814']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end

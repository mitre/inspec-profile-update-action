control 'SV-219154' do
  title 'The Ubuntu operating system must have a crontab script running weekly to off-load audit events of standalone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', "Verify there is a script which off-loads audit data and if that script runs weekly.

Check if there is a script in the /etc/cron.weekly directory which off-loads audit data:

# sudo ls /etc/cron.weekly

audit-offload

Check if the script inside the file does offloading of audit logs to an external media.

If the script file does not exist or if the script file doesn't offload audit logs, this is a finding."
  desc 'fix', 'Create a script which off-loads audit logs to external media and runs weekly.

Script must be located into the /etc/cron.weekly directory.'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20879r304790_chk'
  tag severity: 'low'
  tag gid: 'V-219154'
  tag rid: 'SV-219154r610963_rule'
  tag stig_id: 'UBTU-18-010008'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-20878r304791_fix'
  tag 'documentable'
  tag legacy: ['SV-109637', 'V-100533']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

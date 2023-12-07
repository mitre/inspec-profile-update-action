control 'SV-27367' do
  title 'The cron.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the cron.allow file is not set to root, bin, or sys, the possibility exists for an unauthorized user to view or to edit sensitive information.'
  desc 'check', '# ls -lL /var/adm/cron/cron.allow

If the cron.allow file is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', '# chown root /var/adm/cron/cron.allow'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28511r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4361'
  tag rid: 'SV-27367r1_rule'
  tag stig_id: 'GEN003240'
  tag gtitle: 'GEN003240'
  tag fix_id: 'F-24612r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-38550' do
  title 'The cronlog file must have mode 0600 or less permissive.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', 'Check the mode of the cron log file.
# ls -lL /var/adm/cron/log

If the mode is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron log file.
# chmod 0600 /var/adm/cron/log'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36456r1_chk'
  tag severity: 'medium'
  tag gid: 'V-983'
  tag rid: 'SV-38550r1_rule'
  tag stig_id: 'GEN003180'
  tag gtitle: 'GEN003180'
  tag fix_id: 'F-31795r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-27357' do
  title 'The cronlog file must have mode 0600 or less permissive.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'fix', 'Change the mode of the cron log file.
# chmod 0600 /var/log/cron'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-983'
  tag rid: 'SV-27357r2_rule'
  tag stig_id: 'GEN003180'
  tag gtitle: 'GEN003180'
  tag fix_id: 'F-24602r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

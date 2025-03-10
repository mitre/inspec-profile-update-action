control 'SV-983' do
  title 'The cron log file must have mode 0600 or less permissive.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', 'Check the mode of the system cron log.  If the mode is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the system cron log to 0600.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-792r2_chk'
  tag severity: 'medium'
  tag gid: 'V-983'
  tag rid: 'SV-983r2_rule'
  tag stig_id: 'GEN003180'
  tag gtitle: 'GEN003180'
  tag fix_id: 'F-1137r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-982' do
  title 'Cron logging must be implemented.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs.  It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  desc 'check', 'Determine if cron logging is enabled on the system.  If cron logging is not enabled, this is a finding.'
  desc 'fix', 'Enable cron logging on the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-791r2_chk'
  tag severity: 'medium'
  tag gid: 'V-27353'
  tag rid: 'SV-982r2_rule'
  tag stig_id: 'GEN003160'
  tag gtitle: 'GEN003160'
  tag fix_id: 'F-1136r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000872']
  tag nist: ['MA-3 (4)']
end

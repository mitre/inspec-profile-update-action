control 'SV-26038' do
  title 'The cron log files must not have extended ACLs.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', 'Determine if the cron log file has an extended ACL.  If it does, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the cron log file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29219r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22388'
  tag rid: 'SV-26038r1_rule'
  tag stig_id: 'GEN003190'
  tag gtitle: 'GEN003190'
  tag fix_id: 'F-26240r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

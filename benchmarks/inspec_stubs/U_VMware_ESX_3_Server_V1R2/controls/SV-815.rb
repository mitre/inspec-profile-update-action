control 'SV-815' do
  title 'The audit system must be configured to audit file deletions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the system audit configuration.  If the system is not configured to audit file and program deletion, this is a finding.'
  desc 'fix', 'Configure the system to audit file and program deletion.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-557r2_chk'
  tag severity: 'medium'
  tag gid: 'V-815'
  tag rid: 'SV-815r2_rule'
  tag stig_id: 'GEN002740'
  tag gtitle: 'GEN002740'
  tag fix_id: 'F-969r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

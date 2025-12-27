control 'SV-814' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the audit configuration to determine if failed attempts to access files and programs are audited.  If they are not, this is a finding.'
  desc 'fix', 'Configure the system to audit failed attempts to access files and programs.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-556r2_chk'
  tag severity: 'medium'
  tag gid: 'V-814'
  tag rid: 'SV-814r2_rule'
  tag stig_id: 'GEN002720'
  tag gtitle: 'GEN002720'
  tag fix_id: 'F-968r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

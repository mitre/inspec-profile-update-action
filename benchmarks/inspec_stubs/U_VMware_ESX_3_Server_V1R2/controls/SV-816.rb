control 'SV-816' do
  title 'The audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the system configuration to determine if all administrative, privileged, and security actions are audited.  If any of these categories of events is not audited, this is a finding.'
  desc 'fix', 'Configure the system to audit all administrative, privileged, and security actions.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-558r2_chk'
  tag severity: 'medium'
  tag gid: 'V-816'
  tag rid: 'SV-816r2_rule'
  tag stig_id: 'GEN002760'
  tag gtitle: 'GEN002760'
  tag fix_id: 'F-970r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000347']
  tag nist: ['CM-5 (1)']
end

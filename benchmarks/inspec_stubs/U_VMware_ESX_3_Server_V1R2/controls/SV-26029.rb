control 'SV-26029' do
  title 'The audit system must be configured to audit account termination.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Determine if the system is configured to audit account termination.  If it is not, this is a finding.'
  desc 'fix', 'Configure the system to audit account termination.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29212r1_chk'
  tag severity: 'low'
  tag gid: 'V-22382'
  tag rid: 'SV-26029r1_rule'
  tag stig_id: 'GEN002753'
  tag gtitle: 'GEN002753'
  tag fix_id: 'F-26232r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end

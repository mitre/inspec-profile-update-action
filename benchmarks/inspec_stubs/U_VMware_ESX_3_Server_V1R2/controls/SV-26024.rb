control 'SV-26024' do
  title 'The audit system must be configured to audit account modification.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Determine if the audit system is configured to audit account modification.  If it is not, this is a finding.'
  desc 'fix', 'Configure the system to audit account modification.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29210r1_chk'
  tag severity: 'low'
  tag gid: 'V-22377'
  tag rid: 'SV-26024r1_rule'
  tag stig_id: 'GEN002751'
  tag gtitle: 'GEN002751'
  tag fix_id: 'F-26230r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end

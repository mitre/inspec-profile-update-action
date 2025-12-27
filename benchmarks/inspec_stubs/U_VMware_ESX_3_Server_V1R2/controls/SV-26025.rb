control 'SV-26025' do
  title 'The audit system must be configured to audit account disabling.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Determine if the system is configured to audit account disabling.  If not, this is a finding.'
  desc 'fix', 'Configure the system to audit account disabling.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29211r1_chk'
  tag severity: 'low'
  tag gid: 'V-22378'
  tag rid: 'SV-26025r1_rule'
  tag stig_id: 'GEN002752'
  tag gtitle: 'GEN002752'
  tag fix_id: 'F-26231r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end

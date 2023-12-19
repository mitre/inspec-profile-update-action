control 'SV-818' do
  title 'The audit system must be configured to audit login, logout, and session initiation.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Verify the system is configured to audit login, logout, and session initiation.  If the system does not audit any of these events, this is a finding.'
  desc 'fix', 'Configure the system to audit login, logout, and session initiation.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-561r2_chk'
  tag severity: 'medium'
  tag gid: 'V-818'
  tag rid: 'SV-818r2_rule'
  tag stig_id: 'GEN002800'
  tag gtitle: 'GEN002800'
  tag fix_id: 'F-973r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

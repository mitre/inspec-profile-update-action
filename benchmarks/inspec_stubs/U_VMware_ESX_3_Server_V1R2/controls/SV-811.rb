control 'SV-811' do
  title 'Auditing must be implemented.'
  desc 'Without auditing, individual system accesses cannot be tracked and malicious activity cannot be detected and traced back to an individual account.'
  desc 'check', 'Determine if auditing is enabled.  If auditing is not enabled, this is a finding.'
  desc 'fix', 'Configure the system to implement auditing.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-553r2_chk'
  tag severity: 'medium'
  tag gid: 'V-811'
  tag rid: 'SV-811r2_rule'
  tag stig_id: 'GEN002660'
  tag gtitle: 'GEN002660'
  tag fix_id: 'F-965r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end

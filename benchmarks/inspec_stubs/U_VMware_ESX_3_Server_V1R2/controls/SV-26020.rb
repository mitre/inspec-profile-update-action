control 'SV-26020' do
  title 'System audit tool executables must not have extended ACLs.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Determine if system audit tool executables have extended ACLs.  If any do, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the system audit tool executable(s).'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29205r1_chk'
  tag severity: 'low'
  tag gid: 'V-22373'
  tag rid: 'SV-26020r1_rule'
  tag stig_id: 'GEN002718'
  tag gtitle: 'GEN002718'
  tag fix_id: 'F-26226r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end

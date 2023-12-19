control 'SV-26017' do
  title 'System audit tool executables must be owned by root.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Determine if the system audit tool executables are owned by root.  If any are not, this is a finding.'
  desc 'fix', 'Change the owner of the system audit tool executables to root.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29201r1_chk'
  tag severity: 'low'
  tag gid: 'V-22370'
  tag rid: 'SV-26017r1_rule'
  tag stig_id: 'GEN002715'
  tag gtitle: 'GEN002715'
  tag fix_id: 'F-26223r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end

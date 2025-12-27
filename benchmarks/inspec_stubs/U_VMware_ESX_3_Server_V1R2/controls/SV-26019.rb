control 'SV-26019' do
  title 'System audit tool executables must have mode 0750 or less permissive.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Determine if system audit tool executables have a mode more permissive than 0750.  If any do, this is a finding.'
  desc 'fix', 'Change the mode of system audit tool executables to 0750.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29204r1_chk'
  tag severity: 'low'
  tag gid: 'V-22372'
  tag rid: 'SV-26019r1_rule'
  tag stig_id: 'GEN002717'
  tag gtitle: 'GEN002717'
  tag fix_id: 'F-26225r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end

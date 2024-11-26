control 'SV-26512' do
  title 'System audit tool executables must have mode 0750 or less permissive.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'fix', 'As root, change the file permissions.
# chmod 0750 <audit tool executable>'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-22372'
  tag rid: 'SV-26512r2_rule'
  tag stig_id: 'GEN002717'
  tag gtitle: 'GEN002717'
  tag fix_id: 'F-31778r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end

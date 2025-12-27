control 'SV-26506' do
  title 'System audit tool executables must be owned by root.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'fix', 'As root, change the file ownership.
# chown root  <audit_tool_filename>'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-22370'
  tag rid: 'SV-26506r2_rule'
  tag stig_id: 'GEN002715'
  tag gtitle: 'GEN002715'
  tag fix_id: 'F-31776r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end

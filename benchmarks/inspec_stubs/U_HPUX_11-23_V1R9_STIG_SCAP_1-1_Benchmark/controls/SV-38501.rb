control 'SV-38501' do
  title 'All shell files must be owned by root or bin.'
  desc 'If shell files are owned by users other than root or bin, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'fix', 'Change the ownership of any system shell not owned by root or bin:
# chown root <path/shell>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-921'
  tag rid: 'SV-38501r1_rule'
  tag stig_id: 'GEN002200'
  tag gtitle: 'GEN002200'
  tag fix_id: 'F-31750r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

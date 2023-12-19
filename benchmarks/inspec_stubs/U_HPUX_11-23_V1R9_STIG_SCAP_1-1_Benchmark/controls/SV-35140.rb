control 'SV-35140' do
  title 'The hosts.lpd file (or equivalent) must not contain a "+" character.'
  desc 'Having the "+" character in the hosts.lpd (or equivalent) file allows all hosts to use local system print resources.'
  desc 'fix', 'Remove the "+" entries from the hosts.lpd (or equivalent) file.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-827'
  tag rid: 'SV-35140r1_rule'
  tag stig_id: 'GEN003900'
  tag gtitle: 'GEN003900'
  tag fix_id: 'F-30292r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-2, ECCD-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

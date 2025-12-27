control 'SV-38846' do
  title 'All shell files must have mode 0755 or less permissive.'
  desc 'Shells with world/group write permissions give the ability to maliciously modify the shell to obtain unauthorized access.'
  desc 'fix', 'Change the mode of the shell.
# chmod 0755 < shell >'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag severity: 'high'
  tag gid: 'V-922'
  tag rid: 'SV-38846r1_rule'
  tag stig_id: 'GEN002220'
  tag gtitle: 'GEN002220'
  tag fix_id: 'F-33102r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

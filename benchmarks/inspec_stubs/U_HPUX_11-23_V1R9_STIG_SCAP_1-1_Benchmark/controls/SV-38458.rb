control 'SV-38458' do
  title 'All network services daemon files must have mode 0755 or less permissive.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'fix', 'Change the mode of the network services daemon.
# chmod 0755 <path>/<daemon>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-786'
  tag rid: 'SV-38458r1_rule'
  tag stig_id: 'GEN001180'
  tag gtitle: 'GEN001180'
  tag fix_id: 'F-31556r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

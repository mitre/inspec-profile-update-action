control 'SV-786' do
  title 'All network services daemon files must have mode 0755 or less permissive.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'check', 'Check the mode of network services daemon files.  If any have modes more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the network services daemon.
# chmod 0755 <path>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-291r2_chk'
  tag severity: 'medium'
  tag gid: 'V-786'
  tag rid: 'SV-786r2_rule'
  tag stig_id: 'GEN001180'
  tag gtitle: 'GEN001180'
  tag fix_id: 'F-940r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

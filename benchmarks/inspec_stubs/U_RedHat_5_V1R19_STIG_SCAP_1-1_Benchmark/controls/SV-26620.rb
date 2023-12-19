control 'SV-26620' do
  title 'Network interfaces must not be configured to allow user control.'
  desc 'Configuration of network interfaces should be limited to privileged users.  Manipulation of network interfaces may result in a Denial of Service or bypass of network security mechanisms.'
  desc 'fix', 'Edit the configuration for the user-controlled interface and remove the "USERCTL=yes" configuration line or set to "USERCTL=no".'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22408'
  tag rid: 'SV-26620r1_rule'
  tag stig_id: 'GEN003581'
  tag gtitle: 'GEN003581'
  tag fix_id: 'F-23863r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

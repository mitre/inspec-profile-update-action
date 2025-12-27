control 'SV-26069' do
  title 'Network interfaces must not be configured to allow user control.'
  desc 'Configuration of network interfaces should be limited to privileged users.  Manipulation of network interfaces may result in a Denial-of-Service or bypass of network security mechanisms.'
  desc 'check', 'Determine if any network interfaces on the system are configured to allow user control.  If so, this is a finding.'
  desc 'fix', 'Configure network interfaces to not allow user control.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29246r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22408'
  tag rid: 'SV-26069r1_rule'
  tag stig_id: 'GEN003581'
  tag gtitle: 'GEN003581'
  tag fix_id: 'F-26265r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

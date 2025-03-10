control 'SV-207111' do
  title 'The multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.'
  desc 'If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel.

Administrative scoped multicast addresses are locally assigned and are to be used exclusively by the enterprise network or enclave. Administrative scoped multicast traffic must not cross the enclave perimeter in either direction. Restricting multicast traffic makes it more difficult for a malicious user to access sensitive traffic.

Admin-Local scope is encouraged for any multicast traffic within a network intended for network management, as well as for control plane traffic that must reach beyond link-local destinations.'
  desc 'check', 'Review the router configuration and verify that admin-scope multicast traffic is blocked at the external edge.

If the router is not configured to establish boundaries for administratively scoped multicast traffic, this is a finding.'
  desc 'fix', 'Step 1: Configure the ACL to deny packets with multicast administratively scoped destination addresses.

Step 2: Apply the multicast boundary at the appropriate interfaces.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7372r382226_chk'
  tag severity: 'low'
  tag gid: 'V-207111'
  tag rid: 'SV-207111r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000005'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7372r382227_fix'
  tag 'documentable'
  tag legacy: ['SV-69983', 'V-55729']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

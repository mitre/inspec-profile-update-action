control 'SV-75351' do
  title 'The Arista Multilayer Switch must establish boundaries for IPv6 Admin-Local, IPv6 Site-Local, IPv6 Organization-Local scope, and IPv4 Local-Scope multicast traffic.'
  desc 'If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel.

Administrative scoped multicast addresses are locally assigned and are to be used exclusively by the enterprise network or enclave. Administrative scoped multicast traffic must not cross the enclave perimeter in either direction. Restricting multicast traffic makes it more difficult for a malicious user to access sensitive traffic.

Admin-Local scope is encouraged for any multicast traffic within a network intended for network management, as well as for control plane traffic that must reach beyond link-local destinations.'
  desc 'check', 'Review the multicast topology diagram to determine if there are any documented Admin-Local (FFx4::/16), Site-Local (FFx5::/16), or Organization-Local (FFx8::/16) multicast boundaries for IPv6 traffic or any Local-Scope (239.255.0.0/16) boundaries for IPv4 traffic.

Verify the appropriate boundaries are configured on the applicable multicast-enabled interfaces via an "ip multicast boundary" statement in the interface configuration.

If the appropriate boundaries are not configured on applicable multicast-enabled interfaces, this is a finding.'
  desc 'fix', 'Configure the appropriate boundaries to contain packets addressed within the administratively scoped zone. Defined multicast addresses are FFx4::/16, FFx5::/16, FFx8::/16, and 239.255.0.0/16.

To create a PIM Boundary, create an access list by entering:

ip access-list [name]
[ip access list permit/deny statement]
exit

Then apply the boundary filter based on the accesslist to the PIM-enabled interface:

int ethernet [X]
ip multicast boundary [name-of-ACL]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61841r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60893'
  tag rid: 'SV-75351r1_rule'
  tag stig_id: 'AMLS-L3-000130'
  tag gtitle: 'SRG-NET-000019-RTR-000005'
  tag fix_id: 'F-66605r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

control 'SV-88777' do
  title 'The Cisco IOS XE router must establish boundaries for IPv6 Admin-Local, IPv6 Site-Local, IPv6 Organization-Local scope, and IPv4 Local-Scope multicast traffic.'
  desc 'If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel.

Administrative scoped multicast addresses are locally assigned and are to be used exclusively by the enterprise network or enclave. Administrative scoped multicast traffic must not cross the enclave perimeter in either direction. Restricting multicast traffic makes it more difficult for a malicious user to access sensitive traffic.

Admin-Local scope is encouraged for any multicast traffic within a network intended for network management, as well as for control plane traffic that must reach beyond link-local destinations.'
  desc 'check', 'Review the multicast topology diagram to determine if there are any documented Admin-Local (FFx4::/16), Site-Local (FFx5::/16), or Organization-Local (FFx8::/16) multicast boundaries for IPv6 traffic or any Local-Scope (239.255.0.0/16) boundaries for IPv4 traffic.

Verify the appropriate boundaries are configured on the applicable multicast-enabled interfaces. The configuration should look similar to the example below:

interface GigabitEthernet0/0/0
 ip address 192.168.25.75 255.255.255.0
 ip access-group v4_Local_Scope out
 ipv6 address 2001:192:168:25::75/64
 ipv6 multicast boundary scope 4
end

Extended IP access list v4_Local_Scope
    10 deny ip 239.255.0.0 0.0.255.255 any log

Note: The IPv6 scopes are defined as:
 admin-local         Admin-local(4)
 organization-local  Organization-local(8)
 site-local          Site-local(5)

If the appropriate boundaries are not configured on applicable multicast-enabled interfaces, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router with the appropriate IPv6 multicast boundary scopes and with the appropriate IPv4 access control lists, as seen in the example below:

interface GigabitEthernet0/0/0
 ip address 192.168.25.75 255.255.255.0
 ip access-group V4_LOCAL_SCOPE out
 ipv6 address 2001:192:168:25::75/64
 ipv6 multicast boundary scope 4
!
ip access list extended V4_LOCAL_SCOPE
    10 deny ip 239.255.0.0 0.0.255.255 any log

Note:  The IPv6 scopes are defined as follows:
  subnet-local            (3)
  admin-local             (4)
  site-local              (5)
  organization-local      (8)'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74189r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74103'
  tag rid: 'SV-88777r2_rule'
  tag stig_id: 'CISR-RT-000004'
  tag gtitle: 'SRG-NET-000019-RTR-000005'
  tag fix_id: 'F-80645r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

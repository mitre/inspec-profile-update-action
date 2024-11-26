control 'SV-216380' do
  title 'The system must disable network routing unless required.'
  desc "The network routing daemon, in.routed, manages network routing tables. If enabled, it periodically supplies copies of the system's routing tables to any directly connected hosts and networks and picks up routes supplied to it from other networks and hosts.
Routing Internet Protocol (RIP) is a legacy protocol with a number of security weaknesses, including a lack of authentication, zoning, pruning, etc."
  desc 'check', 'Determine if routing is disabled. 

# routeadm -p | egrep "routing |forwarding" | grep enabled

If the command output includes "persistent=enabled" or "current=enabled", this is a finding.'
  desc 'fix', 'The Network Management profile is required.

Disable routing for IPv4 and IPv6.

# pfexec routeadm -d ipv4-forwarding -d ipv4-routing
# pfexec routeadm -d ipv6-forwarding -d ipv6-routing

To apply these changes to the running system, use the command:

# pfexec routeadm -u'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17616r371228_chk'
  tag severity: 'medium'
  tag gid: 'V-216380'
  tag rid: 'SV-216380r603267_rule'
  tag stig_id: 'SOL-11.1-050130'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17614r371229_fix'
  tag 'documentable'
  tag legacy: ['V-48217', 'SV-61089']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

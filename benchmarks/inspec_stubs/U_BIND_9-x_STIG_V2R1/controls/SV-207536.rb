control 'SV-207536' do
  title 'The host running a BIND 9.X implementation must implement a set of firewall rules that restrict traffic on the DNS interface.'
  desc 'Configuring hosts that run a BIND 9.X implementation to only accept DNS traffic on a DNS interface allows a system firewall to be configured to limit the allowed incoming ports/protocols to 53/tcp and 53/udp. Sending outgoing DNS messages from a random port minimizes the risk of an attacker guessing the outgoing message port and sending forged replies.

The TCP/IP stack in DNS hosts (stub resolver, caching/resolving/recursive name server, authoritative name server, etc.) could be subjected to packet flooding attacks (such as SYNC and smurf), resulting in disruption of communication. By implementing a specific set of firewall rules that limit accepted traffic to the interface, these risk of packet flooding and other TCP/IP based attacks is reduced.'
  desc 'check', 'With the assistance of the DNS administrator, verify that the OS firewall is configured to only allow incoming messages on ports 53/tcp and 53/udp.

Note: The following rules are for the IPTables firewall. If the system is utilizing a different firewall, the rules may be different.

Inspect the hosts firewall rules for the following rules:

-A INPUT -i [DNS Interface] -p tcp --dport 53 -j ACCEPT
-A INPUT -i [DNS Interface] -p udp --dport 53 -j ACCEPT
-A INPUT -i [DNS Interface] -j DROP

If any of the above rules do not exist, this is a finding.

If there are rules listed that allow traffic on ports other than 53/tcp and 53/udp, this is a finding.'
  desc 'fix', 'Configure the OS firewall to only allow incoming DNS traffic on ports 53/tcp and 53/udp.
Add the following rules to the host firewall rule set:

# iptables -A INPUT -i [DNS Interface] -p tcp --dport 53 -j ACCEPT
# iptables -A INPUT -i [DNS Interface] -p udp --dport 53 -j ACCEPT
# iptables -A INPUT -i [DNS Interface] -j DROP

Note: If the system is not using an IPTables firewall, the appropriate firewall rules that limit traffic to ports 53/tcp and 53/udp should be configured on the active firewall.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7791r283662_chk'
  tag severity: 'medium'
  tag gid: 'V-207536'
  tag rid: 'SV-207536r612253_rule'
  tag stig_id: 'BIND-9X-001004'
  tag gtitle: 'SRG-APP-000516-DNS-000109'
  tag fix_id: 'F-7791r283663_fix'
  tag 'documentable'
  tag legacy: ['SV-86995', 'V-72371']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

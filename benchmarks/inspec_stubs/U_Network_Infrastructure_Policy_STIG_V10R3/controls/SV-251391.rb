control 'SV-251391' do
  title 'The multicast domain must block inbound and outbound Auto-RP discovery and announcement messages at the edge.'
  desc 'With static RP, the RP address for any multicast group must be consistent across all routers in a multicast domain. A static configuration is simple and convenient. However, if the statically defined RP router becomes unreachable, there is no automatic failover to another RP router. Auto-RP distributes information to routers as to which RP address must be used for various multicast groups. Auto-RP eliminates inconsistencies and enables scalability and automatic failover. All PIM-enabled routers join the RP discovery group (224.0.1.40), which allows them to receive all group-to-RP mapping information. This information is distributed by an entity called RP mapping agent. Mapping agents themselves join the RP announce group (224.0.1.39). All candidate RPs advertise themselves periodically using the RP announce group address. The mapping agent listens to all RP candidate announcements and determines which routers will be used for each multicast group. It then advertises the RP and its associate multicast groups to all PIM routers in the network using an RP discovery message. Auto-RP announcement and discovery messages provide information (i.e., IP addresses of the RP candidates, multicast groups, etc.) vital to the multicast domain and should not be leaked out of the multicast domain. Using this information, a malicious user could disrupt multicast services by attacking the RP or flooding bogus traffic destined to the learned multicast groups.'
  desc 'check', 'To prevent Auto-RP messages from entering or leaving the PIM domain, the ip multicast boundary command must be configured on a COI-facing PIM-enabled interface. Verify that the referenced ACL denies multicast addresses 224.0.1.39 and 224.0.1.40, as shown in the example below:

ip multicast-routing
!
interface FastEthernet0/0
ip address 199.36.92.1 255.255.255.252
ip pim sparse-mode
ip multicast boundary 1
!
access-list 1 deny 224.0.1.39
access-list 1 deny 224.0.1.40

If COI-facing interfaces do not block inbound and outbound Auto-RP discovery and announcement messages, this is a finding.'
  desc 'fix', 'Block inbound and outbound Auto-RP discovery and announcement messages at external-facing PIM-enabled interfaces.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54826r806126_chk'
  tag severity: 'low'
  tag gid: 'V-251391'
  tag rid: 'SV-251391r806128_rule'
  tag stig_id: 'NET2009'
  tag gtitle: 'NET2009'
  tag fix_id: 'F-54779r806127_fix'
  tag 'documentable'
  tag legacy: ['V-66371', 'SV-80861']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

control 'SV-251390' do
  title 'The multicast domain must block inbound and outbound administratively-scoped multicast traffic at the edge.'
  desc 'A multicast boundary must be established to ensure that administratively-scoped multicast traffic does not flow into or out of the IP core. The multicast boundary can be created by ensuring that COI-facing interfaces on all PIM routers are configured to block inbound and outbound administratively-scoped multicast traffic.'
  desc 'check', 'The administratively-scoped IPv4 multicast address space is 239.0.0.0 through 239.255.255.255. Packets addressed to administratively-scoped multicast addresses must not cross administrative boundaries. This can be accomplished by applying a multicast boundary statement to all COI-facing interfaces as shown in the following example:

ip multicast-routing
!
interface FastEthernet0/0
ip address 199.36.92.1 255.255.255.252
ip pim sparse-mode
ip multicast boundary 1
!
access-list 1 deny 239.0.0.0 0.255.255.255 
access-list 1 permit any

If inbound and outbound administratively-scoped multicast traffic is not blocked, this is a finding.'
  desc 'fix', 'Configure a multicast boundary statement at all COI-facing interfaces that has PIM enabled to block inbound and outbound administratively-scoped multicast traffic.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54825r806123_chk'
  tag severity: 'low'
  tag gid: 'V-251390'
  tag rid: 'SV-251390r806125_rule'
  tag stig_id: 'NET2008'
  tag gtitle: 'NET2008'
  tag fix_id: 'F-54778r806124_fix'
  tag 'documentable'
  tag legacy: ['V-66369', 'SV-80859']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

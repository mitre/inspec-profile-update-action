control 'SV-80857' do
  title 'A Protocol Independent Multicast (PIM) neighbor filter must be implemented to restrict and control multicast traffic.'
  desc 'Protocol Independent Multicast (PIM) is a routing protocol that is used by the IP core for forwarding multicast traffic. PIM traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled.'
  desc 'check', 'Step 1: Verify that an ACL is configured that will specify the allowable PIM neighbors similar to the following example.

ip access-list standard pim-neighbors permit 192.0.2.1
permit 192.0.2.3

Step 2: Verify that a pim neighbor-filter command is configured on all PIM enabled interfaces that is referencing the PIM neighbor ACL similar to the following example:

interface GigabitEthernet0/3
ip address 192.0.2.2 255.255.255.0
pim neighbor-filter pim-neighbors

If PIM neighbor filter is not bound to interfaces that have PIM enabled, this is a finding.'
  desc 'fix', 'The router administrator configures and binds a PIM neighbor filter to those interfaces that have PIM enabled.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-67013r1_chk'
  tag severity: 'low'
  tag gid: 'V-66367'
  tag rid: 'SV-80857r1_rule'
  tag stig_id: 'NET2007'
  tag gtitle: 'NET2007'
  tag fix_id: 'F-72443r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

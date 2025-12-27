control 'SV-254048' do
  title 'The Juniper perimeter router must be configured to have Proxy ARP disabled on all external interfaces.'
  desc 'When Proxy ARP is enabled on a router, it allows that router to extend the network (at layer 2) across multiple interfaces (LAN segments). Because proxy ARP allows hosts from different LAN segments to look like they are on the same segment, proxy ARP is only safe when used between trusted LAN segments. Attackers can leverage the trusting nature of proxy ARP by spoofing a trusted host and then intercepting packets. Proxy ARP should always be disabled on router interfaces that do not require it, unless the router is being used as a LAN bridge.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to determine if Proxy ARP is disabled on all external interfaces. By default, Proxy ARP is disabled on all interfaces. Verify "proxy-arp" has not been enabled on external interfaces as shown in the example:

[edit interfaces]
<external interface> {
    unit 0 {
        proxy-arp [restricted|unrestricted]; << Must not be configured on external interfaces.
        <additional configuration>
    }
}

If Proxy ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Disable IP Proxy ARP on all external interfaces.

delete interfaces <external interface> unit 0 proxy-arp'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57500r844175_chk'
  tag severity: 'medium'
  tag gid: 'V-254048'
  tag rid: 'SV-254048r844177_rule'
  tag stig_id: 'JUEX-RT-000760'
  tag gtitle: 'SRG-NET-000364-RTR-000112'
  tag fix_id: 'F-57451r844176_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end

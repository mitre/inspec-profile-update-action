control 'SV-254032' do
  title 'The Juniper router must be configured to have Gratuitous ARP disabled on all external interfaces.'
  desc 'A gratuitous ARP is an ARP broadcast in which the source and destination MAC addresses are the same. It is used to inform the network about a host IP address. A spoofed gratuitous ARP message can cause network mapping information to be stored incorrectly, causing network malfunction.'
  desc 'check', 'Review the configuration to determine if gratuitous ARP is disabled on all external interfaces.
[edit interfaces]
<external interface> {
    no-gratuitous-arp-reply;
    no-gratuitous-arp-request;
    unit <number> {
        family inet {
            address <IPv4 address>/<mask>;
        }
        family inet6 {
            address <IPv6 address>/<mask>;
        }
    }
}

If gratuitous ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable gratuitous ARP on all external interfaces.

set interfaces <external interface> no-gratuitous-arp-reply
set interfaces <external interface> no-gratuitous-arp-request
set interfaces <external interface> unit <number> family inet address <IPv4 address>/<mask>
set interfaces <external interface> unit <number> family inet6 address <IPv6 address>/<prefix>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57484r844127_chk'
  tag severity: 'medium'
  tag gid: 'V-254032'
  tag rid: 'SV-254032r844129_rule'
  tag stig_id: 'JUEX-RT-000600'
  tag gtitle: 'SRG-NET-000362-RTR-000111'
  tag fix_id: 'F-57435r844128_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

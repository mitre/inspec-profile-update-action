control 'SV-253958' do
  title 'The Juniper EX switch must be configured not to forward unknown unicast traffic to access interfaces.'
  desc "Access layer switches use the Content Addressable Memory (CAM) table to direct traffic to specific interfaces based on the VLAN number and the destination MAC address of the frame. When a router has an Address Resolution Protocol (ARP) entry for a destination host and forwards it to the access layer switch and there is no entry corresponding to the frame's destination MAC address in the incoming VLAN, the frame will be sent to all forwarding interfaces within the respective VLAN, which causes flooding. Large amounts of flooded traffic can saturate low-bandwidth links, causing network performance issues or complete connectivity outage to the connected devices. Unknown unicast flooding has been a nagging problem in networks that have asymmetric routing and default timers. To mitigate the risk of a connectivity outage, the unknown unicast traffic must not be flooded to all access interfaces."
  desc 'check', 'Review the switch configuration to verify that unknown unicast frames are forwarded to a single interface.

[edit switch-options]
unknown-unicast-forwarding {
    vlan <VLAN name> {
        interface <interface name>.<logical unit>;
    }
}
Note: Validate the MAC and/or ARP timers are consistent across the network. Blindly forwarding unknown unicast traffic can cause the DoS condition this check intends to prevent. Validate the network architecture and that the receiving interface is appropriate.

If any access VLANs are not configured to forward unknown unicast to a single interface, this is a finding.'
  desc 'fix', 'Configure the switch to have VLANs forward unknown unicast frames to a single interface.

set switch-options unknown-unicast-forwarding vlan <VLAN name> interface <interface name>.<logical unit>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57410r843905_chk'
  tag severity: 'medium'
  tag gid: 'V-253958'
  tag rid: 'SV-253958r843907_rule'
  tag stig_id: 'JUEX-L2-000110'
  tag gtitle: 'SRG-NET-000362-L2S-000024'
  tag fix_id: 'F-57361r843906_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

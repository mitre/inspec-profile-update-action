control 'SV-253967' do
  title 'The Juniper EX switch must not be configured with VLANs used for L2 control traffic assigned to any host-facing access interface.'
  desc 'In a switched Ethernet network, some protocols use L2 Protocol Data Units (PDU) to communicate in-band management or other control information. This control traffic is inappropriate for host-facing access interfaces because those devices are not part of the switching infrastructure. Juniper switches do not automatically carry this L2 control traffic in the default VLAN or automatically assign the default VLAN to all trunks, reducing the scope of potential misuse. Preventing host-facing access interfaces from participating in the L2 control traffic communications further reduces the risk of inadvertent (or malicious) interference.'
  desc 'check', 'Review the switch configurations and verify all access interfaces are assigned to a configured VLAN not used for L2 control traffic.

If assigning via interface-range, the configuration will be similar to the example.
[edit interfaces]
interface-range <name> {
    member <interface name>;
    member-range <starting interface name> to <ending interface name>; <<< Member ranges are contiguous from <start interface> to <end interface> inclusive
    unit 0 {
        family ethernet-switching {
            vlan {
                members <vlan name>;
            }
        }
    }
}

If assigning individually, the configuration will be similar to the example.
[edit interfaces]
<interface name> {
    unit 0 {
        family ethernet-switching {
            vlan {
                members <vlan name>;
            }
        }
    }
}

Verify the assigned VLANs are configured. 
[edit vlans]
<vlan name> {
    vlan-id <VLAN ID>;
}
Note: Assigning interfaces to a VLAN automatically removes them from the default VLAN.

If there are access interfaces assigned to the VLANs used for L2 control traffic, this is a finding.'
  desc 'fix', 'Assign all access interfaces to a VLAN not used for L2 control traffic.

Interface range configuration:
set interfaces interface-range name member <interface name>
set interfaces interface-range name member-range <starting interface name> to <ending interface name>
set interfaces interface-range name unit 0 family ethernet-switching vlan members <vlan name>

Individual interface configuration:
set interfaces <interface name> unit 0 family ethernet-switching vlan members <vlan name>

Configure the VLAN:
set vlans <vlan name> vlan-id <VLAN ID>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57419r843932_chk'
  tag severity: 'medium'
  tag gid: 'V-253967'
  tag rid: 'SV-253967r843934_rule'
  tag stig_id: 'JUEX-L2-000200'
  tag gtitle: 'SRG-NET-000512-L2S-000008'
  tag fix_id: 'F-57370r843933_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

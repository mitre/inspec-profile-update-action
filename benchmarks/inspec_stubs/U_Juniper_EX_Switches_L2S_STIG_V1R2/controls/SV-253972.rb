control 'SV-253972' do
  title 'The Juniper EX switch must not have any access interfaces assigned to a VLAN configured as native for any trunked interface.'
  desc 'Trunked interfaces without an assigned native VLAN do not accept untagged data packets. Allowing trunked interfaces to accept untagged data packets may unintentionally expose VLANs to unauthorized devices that could result in network exploration, unauthorized resource access, or a DoS condition. If a network function requires a native VLAN, and access interfaces are members of the assigned VLAN, authorized devices connected to those interfaces may gain unauthorized access to protected resources.'
  desc 'check', 'Review the switch configurations and examine all access interfaces. Verify that they do not belong to any VLAN configured as native for any trunked interface.

Example trunked interface with native VLAN ID 30 and an access interface configured for vlan_name:
[edit interfaces]
<trunk interface name> {
    native-vlan-id 30;
    unit 0 {
        family ethernet-switching {
            interface-mode trunk;
            vlan {
                members [ <vlan name> ... <vlan name> ];
            }
        }
    }
}
<access interface name> {
    unit 0 {
        family ethernet-switching {
            interface-mode access;
            vlan {
                members vlan_name;
            }
        }
    }
}

Example VLANs (vlan-id 30 is configured on a trunked interface as native and must not be assigned to access interfaces):
[edit vlans]
vlan_30 {
    vlan-id 30;
}
vlan_name {
    vlan-id <VLAN ID not 30>;
}

If trunked interfaces are not configured with a native VLAN ID, this is not a finding.

If any trunked interface is configured with a native VLAN ID, and any access interfaces have been assigned to the same VLAN, this is a finding.'
  desc 'fix', 'Configure all access interfaces with a VLAN separate from any VLAN configured as native on any trunked interface.

set interfaces <interface name> unit 0 family ethernet-switching interface-mode access
set interfaces <interface name> unit 0 family ethernet-switching vlan members vlan_name 

set vlans <vlan_name> vlan-id <VLAN ID not assigned as native to any trunked interface>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57424r843947_chk'
  tag severity: 'low'
  tag gid: 'V-253972'
  tag rid: 'SV-253972r843949_rule'
  tag stig_id: 'JUEX-L2-000250'
  tag gtitle: 'SRG-NET-000512-L2S-000013'
  tag fix_id: 'F-57375r843948_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

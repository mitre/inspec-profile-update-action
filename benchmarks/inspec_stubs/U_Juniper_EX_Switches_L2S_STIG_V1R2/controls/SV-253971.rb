control 'SV-253971' do
  title 'The Juniper EX switch must not have a native VLAN ID assigned, or have a unique native VLAN ID, for all 802.1q trunk links.'
  desc 'By default, Juniper switches do not assign a native VLAN to any trunked interface. Allowing trunked interfaces to accept untagged data packets may unintentionally expose VLANs to unauthorized devices that could result in network exploration, unauthorized resource access, or a DoS condition. If a network function requires a native VLAN it must be unique.'
  desc 'check', 'Review the switch configuration and examine all trunked interfaces to verify no native VLAN ID is assigned. If a native VLAN has been assigned, verify the VLAN is unique.

By default, there are no native VLANs assigned to any trunked interface.

Verify trunked interface do not have a native VLAN ID configured.
[edit interfaces]
<interface name> {
    unit 0 {
        family ethernet-switching {
            interface-mode trunk;
            vlan {
                members [ vlan_name ... vlan_name ];
            }
        }
    }
}

If trunked interfaces require a native VLAN, verify it is unique.
[edit interfaces]
<interface name> {
    native-vlan-id <unique VLAN ID>;
    unit 0 {
        family ethernet-switching {
            interface-mode trunk;
            vlan {
                members [ vlan_name ... vlan_name ];
            }
        }
    }
}
Note: By default, Juniper switches do not automatically assign a native VLAN. Configuring an interface with "interface-mode trunk" does not automatically assign the default VLAN.

Verify any VLAN assigned as native for any trunked interface has been configured.
[edit vlans]
native_vlan_name {
    vlan-id <VLAN ID>;
}

If trunked interfaces do not have a native VLAN ID configured, this is not a finding.

If a native VLAN is configured and does not have a unique VLAN ID, this is a finding.'
  desc 'fix', 'To ensure the integrity of the trunk link, either remove the native VLAN ID or configure the native VLAN ID with a unique value. If used, the native VLAN ID must be the same on both ends of the trunk link. 

Example deleting a native VLAN ID:
delete interfaces <interface name> native-vlan-id

Example configuring a native VLAN ID:
set interfaces <interface name> native-vlan-id <VLAN ID not 1>

Example configuring a VLAN used as native for any trunked interface:
set vlans vlan_name vlan-id 30'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57423r843944_chk'
  tag severity: 'medium'
  tag gid: 'V-253971'
  tag rid: 'SV-253971r843946_rule'
  tag stig_id: 'JUEX-L2-000240'
  tag gtitle: 'SRG-NET-000512-L2S-000012'
  tag fix_id: 'F-57374r843945_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

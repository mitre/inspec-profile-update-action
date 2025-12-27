control 'SV-253966' do
  title 'The Juniper EX switch must be configured to assign all disabled access interfaces to an unused VLAN.'
  desc 'It is possible that a disabled access interface that is assigned to a user or management VLAN becomes enabled by accident or by an attacker and as a result gains access to that VLAN as a member.'
  desc 'check', 'Review the switch configurations and examine all access interfaces. Each access interface not in use should have membership in an inactive VLAN that is not used for any purpose and is not allowed on any trunk links.

Verify a VLAN is configured for unused interfaces.
[edit vlans]
vlan_disabled {
    vlan-id <VLAN ID>;
}

Verify disabled interfaces are assigned to an unused VLAN either individually or via the "interface-range" command. Verify interfaces configured via "interface-range" are not also configured individually.
Multiple interfaces simultaneously configured via interface-range.
[edit interfaces]
interface-range <name> {
    member <interface name>;
    member-range <starting interface name> to <ending interface name>; <<< Member ranges are contiguous from <start interface> to <end interface> inclusive
    disable;
    unit 0 {
        family ethernet-switching {
            vlan {
                members vlan_disabled;
            }
        }
    }
}

Individually configured:
[edit interfaces]
<interface name> {
    disable;
    unit 0 {
        family ethernet-switching {
            vlan {
                members vlan_disabled;
            }
        }
    }
}

In this example, "vlan_disabled" is designated for all unused interfaces and must not be configured on any trunked interface. Verify the unused VLAN is NOT a member of any trunked interface as in the example below.
[edit interfaces]
<interface name> {
    unit <logical unit> {
        family {
            ethernet-switching {
                interface-mode trunk;
                vlan {
                    members [ vlan_name vlan_disabled ];
                }
            }
        }
    }
}
If there are any access interfaces not in use and not in an inactive VLAN, this is a finding.

Note: Access interfaces configured for 802.1x are exempt from this requirement.'
  desc 'fix', 'Disable all access interfaces not in use and assign to an inactive VLAN.

In this example, "vlan_disabled" is the name given to the VLAN for unused interfaces. This VLAN name can be any legal name.

set vlans vlan_disabled vlan-id <VLAN ID>

set interfaces interface-range <name> member <interface name>
set interfaces interface-range <name> member-range <starting interface name> to <ending interface name>
set interfaces interface-range <name> disable
set interfaces interface-range <name> unit 0 family ethernet-switching vlan members vlan_disabled

set interfaces <interface name> disable
set interfaces <interface name> unit 0 family ethernet-switching vlan members vlan_disabled

Delete the unused VLAN from all trunked interfaces.

delete interfaces <trunked interface> unit 0 family ethernet-switching vlan members vlan_disabled

Note: Switch ports configured for 802.1x are exempt from this requirement.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57418r843929_chk'
  tag severity: 'medium'
  tag gid: 'V-253966'
  tag rid: 'SV-253966r843931_rule'
  tag stig_id: 'JUEX-L2-000190'
  tag gtitle: 'SRG-NET-000512-L2S-000007'
  tag fix_id: 'F-57369r843930_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

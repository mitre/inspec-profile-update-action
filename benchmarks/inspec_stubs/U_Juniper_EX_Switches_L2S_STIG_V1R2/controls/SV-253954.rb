control 'SV-253954' do
  title 'The Juniper EX switch must be configured to authenticate all network-connected endpoint devices before establishing any connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including, but not limited to, workstations, printers, servers (outside a datacenter), VoIP Phones, and VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply.

Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system.'
  desc 'check', 'Verify the switch configuration has 802.1x authentication implemented for all access interfaces connecting to LAN outlets (i.e., RJ-45 wall plates) or devices not located in the telecom room, wiring closets, or equipment rooms. Static MAC Bypass or MAC RADIUS must be configured on  access interfaces connected to devices that do not support an 802.1x supplicant. Junos supports three supplicant types: single-secure (authenticate and permit only a single device), multiple (separately authenticate and permit multiple devices), and single (authenticate the first supplicant and permit all others).

Verify that the RADIUS server(s) are configured. RADIUS servers can be configured globally at [edit access radius-server] or defined for each group.
[edit access]
radius-server {
    <RADIUS IPv4 or IPv6 address> secret "PSK"; ## SECRET-DATA
}
profile dot1x_radius {
    authentication-order radius;
    radius {
        authentication-server <RADIUS IPv4 or IPv6 address>; <<< Must be defined if using global RADIUS server. Optional if RADIUS is defined specifically for the profile.
    }
    radius-server {
        <RADIUS IPv4 or IPv6 address> secret "PSK"; ## SECRET-DATA <<< Must be defined if not using global RADIUS server. Takes precedence if both profile and global RADIUS is configured.
    }
}

Verify 802.1x or MAC RADIUS is configured on all host-facing access interfaces when RADIUS is available as shown in the following example:
[edit protocols dot1x]
authenticator {
    authentication-profile-name dot1x_radius;
    interface {
        ge-0/0/0.0 {  <<< Connected device with 802.1x supplicant
            supplicant single-secure;
        }
        ge-0/0/1.0 {  <<< Connected device with 802.1x supplicant and interface support for MAC RADIUS
            supplicant multiple;
            mac-radius;
        }
        ge-0/0/2.0 {  <<< Connected device without 802.1x supplicant
            mac-radius {
                restrict;
            }
        }
    }
}
Note: Junos simultaneously supports both 802.1x and MAC RADIUS on the same access interface. To prevent 802.1x and have the interface use only MAC RADIUS, configure the "restrict" qualifier.

If RADIUS is unavailable or not configured:
[edit protocols]
dot1x {
    authenticator {
        static {
           <MAC address>/48 {
                vlan-assignment <vlan name>;
                interface <interface name>.<logical unit>;
            }
        }
    }
}

If 802.1x authentication, Static MAC Bypass, or MAC RADIUS is not configured on all access interfaces connecting to LAN outlets or devices not located in the telecom room, wiring closets, or equipment rooms, this is a finding.'
  desc 'fix', 'Configure 802.1 x authentication on all host-facing access interfaces. To authenticate those devices that do not support an 802.1x supplicant, Static MAC Bypass or MAC RADIUS must be configured.

Configure RADIUS if available:
set access radius-server <RADIUS IPv4 or IPv6 address (global)> secret "<PSK>"
set access profile dot1x_radius radius authentication-server <RADIUS IPv4 or IPv6 address (global)>
-or-
set access profile dot1x_radius radius-server <RADIUS IPv4 or IPv6 address> secret "<PSK>"

set access profile dot1x_radius authentication-order radius

To configure 802.1x on an access interface:
set protocols dot1x authenticator authentication-profile-name dot1x_radius
set protocols dot1x authenticator interface ge-0/0/0.0 supplicant single-secure
set protocols dot1x authenticator interface ge-0/0/1.0 supplicant multiple
set protocols dot1x authenticator interface ge-0/0/1.0 mac-radius
set protocols dot1x authenticator interface ge-0/0/2.0 mac-radius restrict

To configure Static MAC Bypass:
set protocols dot1x authenticator static <MAC address>/48 vlan-assignment <vlan name>
set protocols dot1x authenticator static <MAC address>/48 interface <interface name>.<logical unit>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57406r843893_chk'
  tag severity: 'medium'
  tag gid: 'V-253954'
  tag rid: 'SV-253954r843895_rule'
  tag stig_id: 'JUEX-L2-000070'
  tag gtitle: 'SRG-NET-000343-L2S-000016'
  tag fix_id: 'F-57357r843894_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end

control 'SV-253949' do
  title 'The Juniper EX switch must be configured to uniquely identify all network-connected endpoint devices before establishing any connection.'
  desc 'Controlling LAN access via 802.1x authentication can assist in preventing a malicious user from connecting an unauthorized PC to an access interface to inject or receive data from the network without detection.

802.1x includes Static MAC Bypass and MAC RADIUS for those devices that do not offer a supplicant.'
  desc 'check', %q(Verify the switch configuration has 802.1x authentication implemented for all access interfaces connecting to LAN outlets (i.e., RJ-45 wall plates) or devices not located in the telecom room, wiring closets, or equipment rooms. Static MAC Bypass or MAC RADIUS must be configured on  access interfaces connected to devices that do not support an 802.1x supplicant. Junos supports three supplicant types: 'single-secure' (authenticate and permit only a single device), 'multiple' (separately authenticate and permit multiple devices), and 'single' (authenticate the first supplicant and permit all others).

Verify that the RADIUS server(s) are configured. RADIUS servers can be configured globally at [edit access radius-server] or defined for each group.
[edit access]
radius-server {
    <RADIUS IPv4 or IPv6 address> secret "PSK"; ## SECRET-DATA
}
profile dot1x_radius {
    authentication-order radius;
    radius {
        authentication-server <RADIUS IPv4 or IPv6 address>;
    }
--or--
    radius-server {
        <RADIUS IPv4 or IPv6 address> secret "PSK"; ## SECRET-DATA
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

If the switch does not uniquely identify all network-connected endpoint devices before establishing any connection for access interfaces connecting to LAN outlets or devices not located in the telecom room, wiring closets, or equipment rooms, this is a finding.)
  desc 'fix', 'Configure 802.1 x authentication on all host-facing access interfaces. To authenticate those devices that do not support an 802.1x supplicant, Static MAC Bypass or MAC RADIUS must be configured.

Configure RADIUS if available:
set access radius-server <RADIUS IPv4 or IPv6 address> secret "<PSK>"
set access profile dot1x_radius radius authentication-server <RADIUS IPv4 or IPv6 address>
-or-
set access profile dot1x_radius radius-server <RADIUS IPv4 or IPv6 address> secret "<PSK>"

set access profile dot1x_radius authentication-order radius

To configure 802.1x on an access interface:
set protocols dot1x authenticator authentication-profile-name dot1x_radius
set protocols dot1x authenticator interface <name>.<logical unit> supplicant single-secure
--or--
set protocols dot1x authenticator interface <name>.<logical unit> supplicant multiple
--or--
set protocols dot1x authenticator interface <name>.<logical unit> supplicant multiple
set protocols dot1x authenticator interface <name>.<logical unit> mac-radius
set protocols dot1x authenticator interface <name>.<logical unit> mac-radius restrict
Note: Configure the "restrict" keyword if the connected device does not support a supplicant. Although a non 802.1x aware client will use MAC RADIUS if configured, without the "restrict" keyword 802.1x authentication is attempted before attempting MAC RADIUS, which increases the time the device must wait before gaining network access.

To configure Static MAC Bypass:
set protocols dot1x authenticator static <MAC address>/48 vlan-assignment <vlan name>
set protocols dot1x authenticator static <MAC address>/48 interface <interface name>.<logical unit>'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57401r843878_chk'
  tag severity: 'high'
  tag gid: 'V-253949'
  tag rid: 'SV-253949r843880_rule'
  tag stig_id: 'JUEX-L2-000020'
  tag gtitle: 'SRG-NET-000148-L2S-000015'
  tag fix_id: 'F-57352r843879_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end

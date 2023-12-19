control 'SV-253970' do
  title 'The Juniper EX switch must be configured to set all user-facing or untrusted ports as access interfaces.'
  desc 'Configuring user-facing or untrusted interfaces as trunked may expose network traffic to an unauthorized, or unintended, connected endpoint. Access interfaces can belong to a single VLAN rather than the multiple VLANs supported by trunks, which limits potential exposure to a smaller subset of the total network traffic.

Access interfaces also behave differently than trunked interfaces, especially with respect to control plane traffic. For example, access interfaces can be marked as "edge" for protocols like Rapid Spanning Tree (RSTP) or Multiple Spanning Tree (MSTP) where specific protections can be applied to prevent the switch from accepting Bridge Protocol Data Units (BPDU) from unauthorized sources and causing a network topology change or disruption. Additionally, network level protection mechanisms, like 802.1x or sticky-mac, are applied to access interfaces and these protection mechanisms help prevent unauthorized network access.'
  desc 'check', 'Review the switch configuration and examine all user-facing or untrusted interfaces and verify the interface mode command is not present or, if present, is not configured with the keyword "trunk".

Default interface-mode access for interface configured with family ethernet-switching.
[edit interfaces]
<interface name> {
    unit 0 {
        family ethernet-switching {
        }
    }
}
Note: Because the default interface-mode is "access", an interface configured for family ethernet-switching and without an "interface-mode" declaration is automatically an access interface.

Interfaces explicitly configured mode access.
[edit interfaces]
<interface name> {
    unit 0 {
        family ethernet-switching {
            interface-mode access;
        }
    }
}

If any of the user-facing access interfaces are configured as a trunk, this is a finding.'
  desc 'fix', 'Disable trunking on all user-facing or untrusted access interfaces.

Deleting interface-mode from the configuration automatically assigns mode access:
delete interfaces <interface name> unit 0 family ethernet-switching interface-mode

Explicitly configure mode access for a user-facing or untrusted interface:
set interfaces <interface name> unit 0 family ethernet-switching interface-mode access'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57422r843941_chk'
  tag severity: 'medium'
  tag gid: 'V-253970'
  tag rid: 'SV-253970r843943_rule'
  tag stig_id: 'JUEX-L2-000230'
  tag gtitle: 'SRG-NET-000512-L2S-000011'
  tag fix_id: 'F-57373r843942_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

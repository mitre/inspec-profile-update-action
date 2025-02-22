control 'SV-253953' do
  title 'The Juniper EX switch must be configured to permit authorized users to remotely view, in real time, all content related to an established user session from a component separate from the layer 2 switch.'
  desc 'Without the capability to remotely view/hear all content related to a user session, investigations into suspicious user activity would be hampered. Real-time monitoring allows authorized personnel to take action before additional damage is done. The ability to observe user sessions as they are happening allows for interceding in ongoing events that after-the-fact review of captured content would not allow.'
  desc 'check', 'Verify if the switch configuration has an analyzer to capture ingress and egress packets from any designated switch port for the purpose of remotely monitoring a specific user session.  

Packet capture using the [edit forwarding-options analyzer <analyzer name>] configuration will only be present and enabled when actively monitoring sessions.

The Juniper switch supports either output interface or output vlan. To output to a VLAN that is trunked to a remote location, configure the switch with the destination VLAN, configure the uplink interface as trunked, and include the remote analyzer VLAN in the uplink trunk. 

If actively capturing packets, verify an analyzer is present.
[edit vlans]
<destination VLAN name> {
    vlan-id <VLAN ID>;
}

[edit interfaces]
<interface name> {
    unit 0 {
        family ethernet-switching {
            interface-mode trunk;
            vlan {
                members <destination VLAN name>;
            }
        }
    }
}

[edit forwarding-options]
analyzer {
    <analyzer name> {
        input {
            ingress {
                interface <input interface>.<logical unit>;
                -or-
                interface irb.<logical unit>;
            }
            egress {
                interface <input interface>.<logical unit>;
                -or-
                interface irb.<logical unit>;
            }
        output {
            vlan {
                <destination VLAN name>;
            }
        }
    }
}
Note: Simultaneously mirroring both ingress and egress traffic may exceed the output interface capacity. Packet mirroring consumes resources and should only be enabled when actively monitoring sessions.

If active monitoring is not currently required, the lack of an analyzer, or the presence of an inactive (disabled) analyzer, is not a finding.

If the switch is not configured to capture ingress and egress packets from a designated access interface for the purpose of remotely monitoring a specific user session, this is a finding.'
  desc 'fix', 'Enable the feature or configure the switch so that it is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session.

set vlans <destination VLAN name> vlan-id <VLAN ID>

set interfaces <interface name> unit 0 family ethernet-switching interface-mode trunk
set interfaces <interface name> unit 0 family ethernet-switching vlan members <destination VLAN name>

set forwarding-options analyzer <analyzer name> input ingress interface <input interface>.<logical unit>
-or-
set forwarding-options analyzer <analyzer name> input ingress interface irb.<logical unit>

set forwarding-options analyzer <analyzer name> input egress interface <input interface>.<logical unit>
-or-
set forwarding-options analyzer <analyzer name> input egress interface irb.<logical unit>

set forwarding-options analyzer <analyzer name> output vlan <destination VLAN name>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57405r843890_chk'
  tag severity: 'medium'
  tag gid: 'V-253953'
  tag rid: 'SV-253953r843892_rule'
  tag stig_id: 'JUEX-L2-000060'
  tag gtitle: 'SRG-NET-000332-L2S-000002'
  tag fix_id: 'F-57356r843891_fix'
  tag 'documentable'
  tag cci: ['CCI-001920']
  tag nist: ['AU-14 (3)']
end

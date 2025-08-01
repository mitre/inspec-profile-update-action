control 'SV-253965' do
  title 'The Juniper EX switch must be configured to verify two-way connectivity on all interswitch trunked interfaces.'
  desc 'In topologies where fiber optic interconnections are used, physical misconnections can occur that allow a link to appear to be up when there is a mismatched set of transmit/receive pairs. When such a physical misconfiguration occurs, protocols such as STP can cause network instability. OAM LFM and LAG are industry standard layer 2 protocols that can detect these physical misconfigurations by verifying that traffic is flowing bidirectionally between neighbors. Interfaces with OAM configured, and LAG interfaces, periodically transmit packets to neighbor devices. If the packets are not exchanged within a specific time frame, the link is flagged as unidirectional and the interface is shut down. OAM LFM and LAG require both connected devices to be configured.'
  desc 'check', 'If any of the interfaces have fiber optic interconnections with neighbors, review the switch configuration to verify that OAM or LAG is enabled on those interfaces. Because OAM and LAG interfaces exchange packets, the neighbor device must also be configured with OAM or LAG.

Verify OAM connectivity fault management:
[edit protocols oam ethernet link-fault-management]
interface <interface name>;
Note: To enable LFM using default values, specifying the interface is sufficient.

Verify OAM connectivity with custom actions (must match the target environment).
action-profile <profile name> {
    event {
        link-adjacency-loss;
        protocol-down;
        link-event-rate {
            frame-error (1..1000 error(s) per 100 milli-second);
            frame-period (1..100 error(s) per 100 frames);
            frame-period-summary (1..1000 error(s) per second);
            symbol-period (1..100 error(s) per 100 symbol);
        }
    }
    action {
        syslog;
        link-down;
    }
}
interface <interface name-1> {
    apply-action-profile <profile name>;
    pdu-interval (100..1000 milliseconds);
    pdu-threshold (5..10);
    detect-loc;
    link-discovery active;
}
interface <interface name>;

Verify LAG on appropriate interfaces:
[edit interfaces]
<interface name> {
    ether-options {
        802.3ad ae<bundle number>;
    }
}
ae<bundle number> {
    aggregated-ether-options {
        lacp {
            active;
            periodic slow;
        }
    }
    unit 0 {
        family ethernet-switching {
            interface-mode trunk;
            vlan {
                members [ vlan_name ... vlan_name ];
            }
        }
    }
}
Note: The bundle number is an integer value that matches the logical LAG interface. For example, physical interface "ge-0/0/0 ether-options 802.3ad ae0" is only associated with the logical LAG bundle "ae0".

If the switch has fiber optic interconnections with neighbors and OAM or LAG is not enabled, this is a finding.'
  desc 'fix', 'Configure the switch to enable OAM or LAG to protect against one-way connections.

LFM with default values:
set protocols oam ethernet link-fault-management interface <interface name>

LAG:
set interfaces <interface name> ether-options 802.3ad ae<bundle number>

set interfaces ae<bundle number> aggregated-ether-options lacp
set interfaces ae<bundle number> unit 0 family ethernet-switching interface-mode trunk
set interfaces ae<bundle number> unit 0 family ethernet-switching vlan members <vlan_name>
:
set interfaces ae<bundle number> unit 0 family ethernet-switching vlan members <vlan_name>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57417r843926_chk'
  tag severity: 'medium'
  tag gid: 'V-253965'
  tag rid: 'SV-253965r843928_rule'
  tag stig_id: 'JUEX-L2-000180'
  tag gtitle: 'SRG-NET-000512-L2S-000004'
  tag fix_id: 'F-57368r843927_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

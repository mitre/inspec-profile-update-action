control 'SV-253964' do
  title 'If STP is used, the Juniper EX switch must be configured to implement Rapid STP, or Multiple STP, where VLANs span multiple switches with redundant links.'
  desc 'Spanning Tree Protocol (STP) is implemented on bridges and switches to prevent layer 2 loops when a broadcast domain spans multiple bridges and switches and when redundant links are provisioned to provide high availability in case of link failures. Convergence time can be significantly reduced using Rapid STP (802.1w) instead of STP (802.1d), resulting in improved availability. Rapid STP should be deployed by implementing either Rapid Spanning-Tree Protocol (RSTP) or Multiple Spanning-Tree Protocol (MSTP), the latter scales much better when there are many VLANs.

In cases where VLANs do not span multiple switches, it is a best practice to not implement STP. Avoiding the use of STP will provide the most deterministic and highly available network topology. If STP is required, then review the switch configuration to verify that Rapid STP or Multiple STP has been implemented. RSTP and MSTP are similar, except MSTP is more granular, flexible, and scalable. RTSP and MSTP can be enabled simultaneously, but in general only one STP is configured.'
  desc 'check', 'If STP is required, then review the switch configuration to verify that Rapid STP or Multiple STP has been implemented. RSTP and MSTP are similar, except MSTP is more granular, flexible, and scalable. RTSP and MSTP can be enabled simultaneously, but in general only one STP is configured.

RSTP:
[edit protocols rstp]
rstp {
    bridge-priority (0..61440 in 4k increments); << e.g. 0, 4k, 8k...60k
    interface <interface name> {
        edge;
    }
    interface <interface name-1> {
        mode point-to-point;
    }
    bpdu-block-on-edge;
}

-OR-

MSTP:
[edit protocols mstp]
configuration-name <name>;
revision-level (0..65535);
max-age (6..40 seconds);
hello-time (1..10 seconds);
forward-delay (4..30 seconds);
bridge-priority (0..61440 in 4k increments); << e.g. 0, 4k, 8k...60k
bpdu-block-on-edge;
interface <interface name> {
    edge;
}
interface <interface name-1> {
    mode point-to-point;
}
msti 3 {
    bridge-priority (0..61440 in 4k increments); << e.g. 0, 4k, 8k...60k
    vlan [ vlan-id-1 vlan-id-2 ];
}
 
If Rapid STP or Multiple STP has not been implemented where an STP is required, this is a finding.'
  desc 'fix', 'Configure Rapid STP to be implemented at the access and distribution layers where VLANs span multiple switches.

RSTP:
set protocols rstp bridge-priority (0..61440 in 4k increments) << e.g. 0, 4k, 8k...60k
set protocols rstp interface <interface name> edge
set protocols rstp interface <interface name-1> mode point-to-point
set protocols rstp bpdu-block-on-edge

MSTP:
set protocols mstp configuration-name <name>
set protocols mstp revision-level (0..65535)
set protocols mstp max-age (6..40 seconds)
set protocols mstp hello-time (1..10 seconds)
set protocols mstp forward-delay (4..30 seconds)
set protocols mstp bridge-priority (0..61440 in 4k increments) << e.g. 0, 4k, 8k...60k
set protocols mstp bpdu-block-on-edge
set protocols mstp interface <interface name> edge
set protocols mstp interface <interface name-1> mode point-to-point
set protocols mstp msti 3 bridge-priority (0..61440 in 4k increments) << e.g. 0, 4k, 8k...60k
set protocols mstp msti 3 vlan <VLAN ID 1>
set protocols mstp msti 3 vlan <VLAN ID 2>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57416r843923_chk'
  tag severity: 'medium'
  tag gid: 'V-253964'
  tag rid: 'SV-253964r843925_rule'
  tag stig_id: 'JUEX-L2-000170'
  tag gtitle: 'SRG-NET-000512-L2S-000003'
  tag fix_id: 'F-57367r843924_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

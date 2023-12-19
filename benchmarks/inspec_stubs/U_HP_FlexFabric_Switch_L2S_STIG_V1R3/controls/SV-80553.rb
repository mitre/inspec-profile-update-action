control 'SV-80553' do
  title 'The HP FlexFabric Switch must have Root Guard enabled on all ports where the root bridge should not appear.'
  desc 'Spanning Tree Protocol (STP) does not provide any means for the network administrator to securely enforce the topology of the switched network. Any switch can be the root bridge in a network. However, a more optimal forwarding topology places the root bridge at a specific predetermined location. With the standard STP, any bridge in the network with a lower bridge ID takes the role of the root bridge. The administrator cannot enforce the position of the root bridge but can set the root bridge priority to 0 in an effort to secure the root bridge position.

The root guard feature provides a way to enforce the root bridge placement in the network. If the bridge receives superior STP Bridge Protocol Data Units (BPDUs) on a root guard-enabled port, root guard moves this port to a root-inconsistent STP state and no traffic can be forwarded across this port while it is in this state. To enforce the position of the root bridge it is imperative that root guard is enabled on all ports where the root bridge should never appear.'
  desc 'check', 'Review the HP FlexFabric Switch topology as well as the configuration to verify that root guard is enabled on switch ports facing users or switches that are downstream from the root bridge.

If the switch has not enabled Root Guard on all ports where the root bridge should not appear, this is a finding.

[HP]display stp
-------[CIST Global Info][Mode MSTP]-------
 Bridge ID           : 0.bcea-fa14-f0a4
 Bridge times        : Hello 2s MaxAge 20s FwdDelay 15s MaxHops 20
 Root ID/ERPC        : 0.bcea-fa14-f0a4, 0
 RegRoot ID/IRPC     : 0.bcea-fa14-f0a4, 0
 RootPort ID         : 0.0
 BPDU-Protection     : Disabled
 Bridge Config-
 Digest-Snooping     : Disabled
 TC or TCN received  : 19824
 Time since last TC  : 0 days 1h:3m:4s

----[Port1(GigabitEthernet1/0/1)][DISCARDING]----
 Port protocol       : Enabled
 Port role           : Designated Port (Boundary)
 Port ID             : 128.1
 Port cost(Legacy)   : Config=auto, Active=20
 Desg.bridge/port    : 0.bcea-fa14-f0a4, 128.1
 Port edged          : Config=disabled, Active=disabled
 Point-to-Point      : Config=auto, Active=true
 Transmit limit      : 10 packets/hello-time
 TC-Restriction      : Disabled
 Role-Restriction    : Disabled
 Protection type     : ROOT'
  desc 'fix', 'Configure the HP FlexFabric Switch to have Root Guard enabled on all ports where the root bridge should not appear.

[HP-GigabitEthernet1/0/1]stp root-protection'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66063'
  tag rid: 'SV-80553r1_rule'
  tag stig_id: 'HFFS-L2-000010'
  tag gtitle: 'SRG-NET-000362-L2S-000021'
  tag fix_id: 'F-72139r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

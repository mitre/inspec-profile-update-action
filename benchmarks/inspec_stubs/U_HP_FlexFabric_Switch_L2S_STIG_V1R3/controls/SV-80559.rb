control 'SV-80559' do
  title 'The HP FlexFabric Switch must have unknown storm-constrain enabled.'
  desc "Access layer switches use the Content Addressable Memory (CAM) table to direct traffic to specific ports based on the VLAN number and the destination MAC address of the frame. When a router has an ARP entry for a destination host and forwards it to the access layer switch and there is no entry corresponding to the frame's destination MAC address in the incoming VLAN, the frame will be sent to all forwarding ports within the respective VLAN, which causes flooding. Large amounts of flooded traffic can saturate low-bandwidth links, causing network performance issues or complete connectivity outage to the connected devices. Unknown unicast flooding has been a nagging problem in networks that have asymmetric routing and default timers. To mitigate the risk of a connectivity outage, the storm-constrain feature must be implemented on all access layer switches. The storm-constrain feature will block unknown unicast traffic flooding and only permit egress traffic with MAC addresses that are known to exit on the port."
  desc 'check', 'Review the HP FlexFabric Switch configuration to verify that unknown storm-constrain is enabled on all access switch ports.

If any access switch ports do not have storm-constrain enabled, this is a finding.

[HP] display storm-constrain
 Abbreviation: BC - broadcast; MC - multicast; UC - unicast
               FW - forwarding
 Flow Statistic Interval: 10 (in seconds)
Port          Type Lower     Upper     Unit CtrlMode Status   Trap Log SwitchNum
--------------------------------------------------------------------------------
XGE1/0/10     UC   1         1         pps  shutdown FW       on   on  0'
  desc 'fix', 'Configure the HP FlexFabric Switch to have unknown storm-constrain  enabled.

[HP-GigabitEthernet1/0/1]storm-constrain unicast pps 1 1

[HP-GigabitEthernet1/0/1]storm-constrain control shutdown'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66713r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66069'
  tag rid: 'SV-80559r1_rule'
  tag stig_id: 'HFFS-L2-000013'
  tag gtitle: 'SRG-NET-000362-L2S-000024'
  tag fix_id: 'F-72145r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

control 'SV-110341' do
  title 'The Cisco switch must have Unknown Unicast Flood Blocking (UUFB) enabled.'
  desc "Access layer switches use the Content Addressable Memory (CAM) table to direct traffic to specific ports based on the VLAN number and the destination MAC address of the frame. When a router has an Address Resolution Protocol (ARP) entry for a destination host and forwards it to the access layer switch and there is no entry corresponding to the frame's destination MAC address in the incoming VLAN, the frame will be sent to all forwarding ports within the respective VLAN, which causes flooding. Large amounts of flooded traffic can saturate low-bandwidth links, causing network performance issues or complete connectivity outage to the connected devices. Unknown unicast flooding has been a nagging problem in networks that have asymmetric routing and default timers. To mitigate the risk of a connectivity outage, the Unknown Unicast Flood Blocking (UUFB) feature must be implemented on all access layer switches. The UUFB feature will block unknown unicast traffic flooding and only permit egress traffic with MAC addresses that are known to exit on the port."
  desc 'check', 'Review the switch configuration to verify that UUFB is enabled on all access switch ports as shown in the configuration example below:

interface Ethernet1/1
 switchport block unicast 

interface Ethernet1/2
 switchport block unicast 
…
…
…
interface Ethernet1/32
 switchport block unicast 

If any access switch ports do not have UUFB enabled, this is a finding.'
  desc 'fix', 'Configure the switch to have Unknown Unicast Flood Blocking (UUFB) enabled as shown in the configuration example below:

SW1(config)# int e1/1-32
SW1(config-if-range)# switchport block unicast 
SW1(config-if-range)# end'
  impact 0.5
  ref 'DPMS Target NX-OS L2 Switch'
  tag check_id: 'C-100117r1_chk'
  tag severity: 'medium'
  tag gid: 'V-101237'
  tag rid: 'SV-110341r1_rule'
  tag stig_id: 'CISC-L2-000120'
  tag gtitle: 'SRG-NET-000362-L2S-000024'
  tag fix_id: 'F-106941r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

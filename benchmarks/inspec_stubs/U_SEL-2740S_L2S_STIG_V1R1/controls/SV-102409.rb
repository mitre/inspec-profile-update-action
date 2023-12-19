control 'SV-102409' do
  title 'The SEL-2740S must be configured to prevent packet flooding and bandwidth saturation.'
  desc "Access layer switches use the Content Addressable Memory (CAM) table to direct traffic to specific ports based on the VLAN number and the destination MAC address of the frame. When a router has an Address Resolution Protocol (ARP) entry for a destination host and forwards it to the access layer switch and there is no entry corresponding to the frame's destination MAC address in the incoming VLAN, the frame will be sent to all forwarding ports within the respective VLAN, which causes flooding. Large amounts of flooded traffic can saturate low-bandwidth links, causing network performance issues or complete connectivity outage to the connected devices. Unknown unicast flooding has been a nagging problem in networks that have asymmetric routing and default timers. To mitigate the risk of a connectivity outage, the Unknown Unicast Flood Blocking (UUFB) feature must be implemented on all access layer switches. The UUFB feature will block unknown unicast traffic flooding and only permit egress traffic with MAC addresses that are known to exit on the port."
  desc 'check', 'Review the SEL-2740S flows to ensure the meter rules are in place to prevent packet flooding and bandwidth saturation.

If the switch is not configured to prevent packet flooding, this is a finding.'
  desc 'fix', 'Add a flow meter rule to prevent packet flooding and bandwidth saturation.

To add an SEL-2740S Flow Meter, do the following:
1. Log on to OTSDN Controller using Permission Level 3.
2. Under "Meter Entry" General settings, select "Meter ID", "Measurement Type", and "Burst Size".
3. Add meter rule to SEL-2740S Flow Rules that require monitoring.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91617r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92321'
  tag rid: 'SV-102409r1_rule'
  tag stig_id: 'SELS-SW-000130'
  tag gtitle: 'SRG-NET-000362-L2S-000024'
  tag fix_id: 'F-98559r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

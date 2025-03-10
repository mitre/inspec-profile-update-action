control 'SV-21787' do
  title 'The LAN Access switch port is NOT configured to place the VVoIP or VTC traffic in the proper VLAN (e.g., the port is NOT assigned to the proper VLAN) or the port does not assign the appropriate VLAN tag via some other method.'
  desc 'Some VVoIP hardware endpoints and hardware based VTC endpoints contain a multi-port Ethernet switch to provide a connection on the endpoint for external devices such as a workstation (i.e., PC port). Additionally, some of these endpoints have the capability of defining the VLAN that their traffic will use via various methods but most typically by using 802.1Q trunking (VLAN tagging). However, some endpoints do not support VLAN assignment or cannot themselves maintain VLAN separation. In these cases, the responsibility of VLAN assignment and maintenance of VLAN separation falls to the LAN access switch (discrete NE or module in a larger NE) that supports the LAN cable drop to which the endpoint(s) is connected. Typically the LAN access switch port configurations contain a statement assigning the port to a specific VLAN.'
  desc 'check', 'If the VVoIP or VTC endpoints DO NOT provide a PC Port (and embedded Ethernet switch or hub), OR they do but cannot support VLAN separation (e.g., they have a hub) OR they cannot tag their traffic with the appropriate VLAN tag ((802.1Q). 

Inspect the configurations of the NE to determine compliance with the following requirement:

In the event a LAN Access switch port supports a VVoIP or VTC endpoint that does not contain a multi-port Ethernet switch OR cannot maintain VLAN separation OR cannot provide an appropriate VLAN tag (802.1Q), ensure the LAN Access switch port is configured to place the VVoIP or VTC traffic in the proper VLAN (e.g., the port is assigned to the VLAN) or the port assigns the appropriate VLAN tag via some other method.  

Look at the LAN access port configurations to determine if the ports are assigned to the appropriate VLAN for the device it supports (VVoIP, VTC, Data, etc) Alternately, look for configuration settings that identify the type of traffic and assign the traffic or the port to the proper VLAN or add the appropriate VLAN tag. 

This is a finding if the initial condition is met and the LAN access ports are not configured as described.'
  desc 'fix', 'In the event a LAN Access switch port supports a VVoIP or VTC endpoint that does not contain a multi-port Ethernet switch OR cannot maintain VLAN separation OR cannot provide an appropriate VLAN tag (802.1Q), ensure the LAN Access switch port is configured to place the VVoIP or VTC traffic in the proper VLAN (e.g., the port is assigned to the VLAN) or the port assigns the appropriate VLAN tag via some other method.  

Configure the LAN access ports such that they are assigned to the appropriate VLAN for the device it supports (VVoIP, VTC, Data, etc) Alternately Configure the LAN access ports to identify the type of traffic and assign the traffic or the port to the proper VLAN or add the appropriate VLAN tag.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19646'
  tag rid: 'SV-21787r2_rule'
  tag stig_id: 'VVoIP 5540'
  tag gtitle: "Deficient imp'n: NE port maint. VLAN sepa’t’n"
  tag fix_id: 'F-20350r1_fix'
  tag 'documentable'
end

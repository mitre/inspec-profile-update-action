control 'SV-77755' do
  title 'The system must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic.'
  desc 'The security issue with vMotion migrations is that information is transmitted in plain text, and anyone with access to the network over which this information flows can view it. Potential attackers can intercept vMotion traffic to obtain memory contents of a virtual machine. They might also potentially stage a MiTM attack in which the contents are modified during migration. 
vMotion traffic must be sequestered from production traffic on an isolated network. This network must be non-routable to other systems preventing outside access to the network.'
  desc 'check', 'The vMotion VMkernel port group should in a dedicated VLAN that can be on a common standard or distributed virtual switch as long as the vMotion VLAN is not shared by any other function and it not routed to anything but ESXi hosts.  The check for this will be unique per environment.  From the vSphere Client select the ESXi host and go to Configuration >> Networking and review the VLAN associated with the vMotion VMkernel(s) and verify they are dedicated for that purpose and are logically separated from other functions.

If long distance or cross vCenter vMotion is used the vMotion network can be routable but must be accessible to only the intended ESXi hosts.

If the vMotion port group is not on an isolated VLAN and/or is routable to systems other than ESXi hosts, this is a finding.

For environments that do not use vCenter server to manage ESXi, this is not applicable.'
  desc 'fix', 'Configuration of the vMotion VMkernel will be unique to each environment. As an example, to modify the IP address and VLAN information to the correct network on a standard switch do the following:

From the vSphere Client select the ESXi host and go to Configuration >> Networking >> On the vSwitch that contains the vMotion VMkernel select Properties.  Select the vMotion VMkernel and click Edit >> On the General tab uncheck everything but "vMotion" and set the appropriate VLAN ID >> Go to the IP Settings tab >> Enter the appropriate IP address and subnet information and click OK.'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63999r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63265'
  tag rid: 'SV-77755r1_rule'
  tag stig_id: 'ESXI-06-000048'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-69183r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

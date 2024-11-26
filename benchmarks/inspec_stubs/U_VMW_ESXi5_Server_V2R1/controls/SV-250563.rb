control 'SV-250563' do
  title 'vMotion traffic must be isolated.'
  desc 'The security issue with vMotion migrations is that information is transmitted in plain text, and anyone with access to the network over which this information flows can view it. Potential attackers can intercept vMotion traffic to obtain memory contents of a virtual machine. They might also potentially stage a MiTM attack in which the contents are modified during migration. 
vMotion traffic must be sequestered from production traffic on an isolated network. This network must be non-routable (no layer-3 router spanning this and other networks), preventing  outside access to the network.'
  desc 'check', 'If vMotion is not used, this check is not applicable.

The vMotion port group must be on a management-only vSwitch to avoid dependency on VLANs for isolation. Verify the vMotion port group vSwitch does not contain any non-management port groups. At least one physical network adaptor must be dedicated to management. To ensure a vMotion vSwitch is on a VMkernel management-only switch, from the vSphere Client/vCenter, select the ESXi host, and select the configuration tab. In the hardware panel, select Networking; locate the vSwitch containing the vMotion port group and visually verify that the vSwitch does not contain any VM Networking or VM references, i.e., the vSwitch must contain management-only, non-production network traffic/functions.

If the vMotion port group is not on a management-only vSwitch, this is a finding.'
  desc 'fix', 'To create a vMotion vSwitch from the vSphere Client/vCenter, select the ESXi host, and select the configuration tab. In the hardware panel, select Networking; click the Add Network link; choose VMKernel and click next; select the desired NIC(s). In the port groups dialog box type a name, (example: "vMotion"). Next, select the "use this port group for vMotion" and set the IP address and subnet mask and gateway where/as required.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53998r798686_chk'
  tag severity: 'low'
  tag gid: 'V-250563'
  tag rid: 'SV-250563r798688_rule'
  tag stig_id: 'ESXI5-VMNET-000021'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53952r798687_fix'
  tag 'documentable'
  tag legacy: ['V-39378', 'SV-51236']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-256411' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic.'
  desc 'While encrypted vMotion is available, vMotion traffic should still be sequestered from other traffic to further protect it from attack. This network must only be accessible to other ESXi hosts, preventing outside access to the network.

The vMotion VMkernel port group must be in a dedicated VLAN that can be on a standard or distributed virtual switch as long as the vMotion VLAN is not shared by any other function and is not routed to anything but ESXi hosts.'
  desc 'check', 'For environments that do not use vCenter server to manage ESXi, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking.

Review the VLAN associated with the vMotion VMkernel(s) and verify they are dedicated for that purpose and are logically separated from other functions.

If long distance or cross vCenter vMotion is used, the vMotion network can be routable but must be accessible to only the intended ESXi hosts.

If the vMotion port group is not on an isolated VLAN and/or is routable to systems other than ESXi hosts, this is a finding.'
  desc 'fix', 'Configuration of the vMotion VMkernel will be unique to each environment.

As an example, to modify the IP address and VLAN information to the correct network on a distributed switch do the following:

From the vSphere Client, go to Networking.

Select a distributed switch, select a port group, and then go to Configure >> Settings >> Edit >> VLAN. 

Change the "VLAN Type" to "VLAN" and change the "VLAN ID" to a network allocated and dedicated to vMotion traffic exclusively.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60086r886012_chk'
  tag severity: 'medium'
  tag gid: 'V-256411'
  tag rid: 'SV-256411r886014_rule'
  tag stig_id: 'ESXI-70-000048'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-60029r886013_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

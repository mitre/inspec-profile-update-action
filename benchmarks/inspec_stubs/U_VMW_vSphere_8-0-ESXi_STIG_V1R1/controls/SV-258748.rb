control 'SV-258748' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic.'
  desc 'While encrypted vMotion is available, vMotion traffic should still be sequestered from other traffic to further protect it from attack. This network must only be accessible to other ESXi hosts, preventing outside access to the network.

The vMotion VMkernel port group must be in a dedicated VLAN that can be on a standard or distributed virtual switch as long as the vMotion VLAN is not shared by any other function and is only routed to ESXi hosts.'
  desc 'check', 'For environments that do not use vCenter server to manage ESXi, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> VMkernel adapters.

Review the VLAN associated with any vMotion VMkernel(s) and verify they are dedicated for that purpose and are logically separated from other functions.

If long distance or cross vCenter vMotion is used, the vMotion network can be routable but must be accessible to only the intended ESXi hosts.

If the vMotion port group is not on an isolated VLAN and/or is routable to systems other than ESXi hosts, this is a finding.'
  desc 'fix', 'Configuration of the vMotion VMkernel will be unique to each environment.

For example, to modify the IP address and VLAN information to the correct network on a distributed switch, do the following:

From the vSphere Client, go to Networking.

Select a distributed switch >> Select a port group >> Configure >> Settings >> Properties.

Click "Edit" and select VLAN.

Change the "VLAN Type" to "VLAN" and change the "VLAN ID" to a network allocated and dedicated to vMotion traffic exclusively. Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62488r933303_chk'
  tag severity: 'medium'
  tag gid: 'V-258748'
  tag rid: 'SV-258748r933305_rule'
  tag stig_id: 'ESXI-80-000160'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-62397r933304_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

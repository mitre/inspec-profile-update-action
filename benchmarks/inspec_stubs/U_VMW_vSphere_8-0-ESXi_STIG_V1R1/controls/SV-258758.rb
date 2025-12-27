control 'SV-258758' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information by isolating ESXi management traffic.'
  desc 'The vSphere management network provides access to the vSphere management interface on each component. Services running on the management interface provide an opportunity for an attacker to gain privileged access to the systems. Any remote attack most likely would begin with gaining entry to this network.

The Management VMkernel port group can be on a standard or distributed virtual switch but must be on a dedicated VLAN. The Management VLAN must not be shared by any other function and must not be accessible to anything other than management-related functions such as vCenter.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> VMkernel adapters.

Review each VMkernel adapter that is used for management traffic and view the "Enabled services".

Review the VLAN associated with each VMkernel that is used for management traffic. Verify with the system administrator that they are dedicated for that purpose and are logically separated from other functions.

If any services other than "Management" are enabled on the Management VMkernel adapter, this is a finding.

If the network segment is accessible, except to networks where other management-related entities are located such as vCenter, this is a finding.

If there are any other systems or devices such as VMs on the ESXi management segment, this is a finding.'
  desc 'fix', 'Configuration of the management VMkernel will be unique to each environment.

For example, to modify the IP address and VLAN information to the correct network on a distributed switch, do the following:

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> VMkernel adapters.

Select the Management VMkernel and click "Edit". On the Port properties tab, uncheck all services except for "Management". Click "OK".

From the vSphere Client, go to Networking.

Select a distributed switch >> Select a port group >> Configure >> Settings >> Properties.

Click "Edit" and select VLAN.

Change the "VLAN Type" to "VLAN" and change the "VLAN ID" to a network allocated and dedicated to management traffic exclusively. Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62498r933333_chk'
  tag severity: 'medium'
  tag gid: 'V-258758'
  tag rid: 'SV-258758r933335_rule'
  tag stig_id: 'ESXI-80-000198'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-62407r933334_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

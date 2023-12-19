control 'SV-256412' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information by protecting ESXi management traffic.'
  desc 'The vSphere management network provides access to the vSphere management interface on each component. Services running on the management interface provide an opportunity for an attacker to gain privileged access to the systems. Any remote attack most likely would begin with gaining entry to this network.

The Management VMkernel port group can be on a standard or distributed virtual switch but must be on a dedicated VLAN. The Management VLAN must not be shared by any other function and must not be accessible to anything other than management-related functions such as vCenter.'
  desc 'check', 'From the vSphere Client, select the ESXi host and go to Configure >> Networking >> VMkernel adapters.

Select each VMkernel adapter that is "Enabled" for management traffic and, in the bottom pane, view the "Enabled services".

If any services other than "Management" are enabled on the Management VMkernel adapter, this is a finding.

From the vSphere Client, select the ESXi host and go to Configure >> Networking >> VMkernel adapters.

Review the VLAN associated with each VMkernel that is "Enabled" for management traffic. Verify with the system administrator that they are dedicated for that purpose and are logically separated from other functions.

If the network segment is accessible, except to networks where other management-related entities are located such as vCenter, this is a finding.

If there are any other systems or devices such as VMs on the ESXi management segment, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> VMkernel adapters.

Select the Management VMkernel and click "Edit...". On the "Port" properties tab, uncheck all services except "Management". Click "OK".

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> Virtual switches.

Find the port group that contains the Management VMkernel and click the "..." button next to the name. Click "Edit Settings".

On the "Properties" tab, change the "VLAN ID" to one dedicated to Management traffic. Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60087r919021_chk'
  tag severity: 'medium'
  tag gid: 'V-256412'
  tag rid: 'SV-256412r919022_rule'
  tag stig_id: 'ESXI-70-000049'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-60030r886016_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

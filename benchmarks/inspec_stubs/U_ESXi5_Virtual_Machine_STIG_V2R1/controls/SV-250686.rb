control 'SV-250686' do
  title 'The system must disable VM-to-VM communication through VMCI.'
  desc 'If the interface is not restricted, a VM can detect and be detected by all other VMs with the same option enabled within the same host. This might be the intended behavior, but custom-built software can have unexpected vulnerabilities that might potentially lead to an exploit. Additionally, it is possible for a VM to detect how many other VMs are within the same ESX system by simply registering the VM. This information might also be used for a potentially malicious objective. By default, the setting is FALSE. The VM can be exposed to other VMs within the same system as long as there is at least one program connected to the VMCI socket interface.'
  desc 'check', %q(Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and locate the VM's vmx file.
# find / | grep vmx

Check the VM's ".vmx" file for the correct "<keyword> = <keyval>" pair.
keyword = vmci0.unrestricted
keyval = FALSE
# grep "^<keyword>" <the VM's vmx file>

If the above command return is either empty or does not reflect the above keyword and keyval value(s), this is a finding.

Re-enable Lockdown Mode on the host.)
  desc 'fix', %q(Configure the VM with the correct "<keyword> = <keyval>" pair. 

To edit a powered-down virtual machine's .vmx file, first remove it from vCenter Server's inventory. Manual additions to the .vmx file from ESXi will be overwritten by any registered entries stored in the vCenter Server database. Make a backup copy of the .vmx file. If the edit breaks the virtual machine, it can be rolled back to the original version of the file. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Storage. 
Right-click on the appropriate datastore and click Browse Datastore. 
Navigate to the folder named after the virtual machine, and locate the <virtual machine>.vmx file. 
Right-click the .vmx file and click Remove from inventory.

Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi host and locate the VM's vmx file. 
# find / | grep vmx

Add the following to the VM's vmx file.
keyword = "keyval"

Where:
keyword = vmci0.unrestricted
keyval = FALSE

Re-enable Lockdown Mode on the host.

Re-register the VM with the vCenter Server:
Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Storage. 
Right-click on the appropriate datastore and click Browse Datastore. 
Navigate to the folder named after the virtual machine, and locate the <virtual machine>.vmx file. 
Right-click the .vmx file and click Add to inventory. The Add to Inventory wizard opens. 
Continue to follow the wizard to add the virtual machine.)
  impact 0.5
  ref 'DPMS Target VMware ESXi Version 5 Virtual Machine'
  tag check_id: 'C-54121r799518_chk'
  tag severity: 'medium'
  tag gid: 'V-250686'
  tag rid: 'SV-250686r799520_rule'
  tag stig_id: 'ESXI5-VM-000011'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54075r799519_fix'
  tag 'documentable'
  tag legacy: ['V-39452', 'SV-51310']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

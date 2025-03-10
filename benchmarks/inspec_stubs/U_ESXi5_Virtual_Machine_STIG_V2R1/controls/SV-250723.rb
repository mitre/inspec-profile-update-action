control 'SV-250723' do
  title 'The system must control access to VMs through VMsafe CPU/memory APIs.'
  desc 'The VMsafe CPU/memory API allows a security virtual machine to inspect and modify the contents of the memory and CPU registers on other VMs, for the purpose of detecting and preventing malware attacks. However, an attacker might compromise the VM by making use of this introspection channel; therefore it should be monitored for unauthorized usage of this API. A VM must be configured explicitly to accept access by the VMsafe CPU/memory API. This involves three parameters: one to enable the API, one to set the IP address used by the security virtual appliance on the introspection vSwitch, and one to set the port number for that IP address. If the VM is being protected by such a product, then make sure the latter two parameters are set correctly. This should be done only for specific VMs for which this protection is wanted.'
  desc 'check', %q(If the VMsafe API is not used, this check is not applicable.

Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and locate the VM's vmx file.
# find / | grep vmx

Check the VM's ".vmx" file for the correct "<keyword> = <keyval>" pair.
keyword = vmsafe.agentAddress
keyval = www.xxx.yyy.zzz (w thru z are integer values of the agent's site-specific IP Address)
# grep "^<keyword>" <the VM's vmx file>

If the above command return is either empty or does not reflect the above keyword and keyval value(s), and the VMsafe API is used, this is a finding.

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
keyword = vmsafe.agentAddress
keyval = www.xxx.yyy.zzz (w thru z are integer values of the agent's site-specific IP Address)

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
  tag check_id: 'C-54158r799629_chk'
  tag severity: 'medium'
  tag gid: 'V-250723'
  tag rid: 'SV-250723r799631_rule'
  tag stig_id: 'ESXI5-VM-000052'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54112r799630_fix'
  tag 'documentable'
  tag legacy: ['SV-51364', 'V-39506']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

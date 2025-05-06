control 'SV-250697' do
  title 'The unexposed feature keyword isolation.tools.ghi.trayicon.disable must be initialized to decrease the VMs potential attack vectors.'
  desc 'Because VMware virtual machines are designed to work on both vSphere, as well as, hosted virtualization platforms, such as Workstation and Fusion, there are some VMX parameters that do not apply when running on vSphere.  Although the functionality governed by these parameters is not exposed on ESX, explicitly disabling them will reduce the potential for vulnerabilities.  Disabling these features reduces the number of vectors through which a guest can attempt to influence the host, and thus may help prevent successful exploits.'
  desc 'check', %q(Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and locate the VM's vmx file.
# find / | grep vmx

Check the VM's ".vmx" file for the correct "<keyword> = <keyval>" pair.
keyword = isolation.tools.ghi.trayicon.disable
keyval = TRUE
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
keyword = isolation.tools.ghi.trayicon.disable
keyval = TRUE

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
  impact 0.3
  ref 'DPMS Target VMware ESXi Version 5 Virtual Machine'
  tag check_id: 'C-54132r799551_chk'
  tag severity: 'low'
  tag gid: 'V-250697'
  tag rid: 'SV-250697r799553_rule'
  tag stig_id: 'ESXI5-VM-000023'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54086r799552_fix'
  tag 'documentable'
  tag legacy: ['V-39479', 'SV-51337']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

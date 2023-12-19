control 'SV-250687' do
  title 'The system must disable VM Monitor Control during normal operation.'
  desc 'When Virtual Machines are running on a hypervisor they are "aware" that they are running in a virtual environment and this information is available to tools inside the guest OS.  This can give attackers information about the platform that they are running on that they may not get from a normal physical server.  This option completely disables all hooks for a virtual machine and the guest OS will not be aware that it is running in a virtual environment at all. This feature may be enabled for short term diagnostics and troubleshooting, but must be disabled prior to resumption of normal operations.'
  desc 'check', %q(Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and locate the VM's vmx file.
# find / | grep vmx

Check the VM's ".vmx" file for the correct "<keyword> = <keyval>" pair.
keyword = isolation.monitor.control.disable
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
keyword = isolation.monitor.control.disable
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
  impact 0.5
  ref 'DPMS Target VMware ESXi Version 5 Virtual Machine'
  tag check_id: 'C-54122r799521_chk'
  tag severity: 'medium'
  tag gid: 'V-250687'
  tag rid: 'SV-250687r799523_rule'
  tag stig_id: 'ESXI5-VM-000013'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54076r799522_fix'
  tag 'documentable'
  tag legacy: ['V-39454', 'SV-51312']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

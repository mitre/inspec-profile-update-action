control 'SV-250717' do
  title 'The system must prevent unauthorized removal, connection and modification of devices by setting the isolation.device.connectable.disable keyword to true.'
  desc 'Normal users and processes-that is, users and processes without root or administrator privileges-within virtual machines have the capability to connect or disconnect devices, such as network adaptors and CD-ROM drives, as well as the ability to modify device settings. In general, the virtual machine settings should use editor or configuration editor to remove any unneeded or unused hardware devices. However, the device may need to be used again, so removing it is not always a good solution. In that case, prevent a user or running process in the virtual machine from connecting or disconnecting a device from within the guest operating system, as well as modifying devices, by adding the following parameters. By default, a rogue user with non-administrator privileges in a virtual machine can connect a disconnected CD-ROM drive and access sensitive information on the media left in the drive.'
  desc 'check', %q(Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and locate the VM's vmx file.
# find / | grep vmx

Check the VM's ".vmx" file for the correct "<keyword> = <keyval>" pair.
keyword = isolation.device.connectable.disable
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
keyword = isolation.device.connectable.disable
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
  tag check_id: 'C-54152r799611_chk'
  tag severity: 'medium'
  tag gid: 'V-250717'
  tag rid: 'SV-250717r799613_rule'
  tag stig_id: 'ESXI5-VM-000045'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54106r799612_fix'
  tag 'documentable'
  tag legacy: ['V-39499', 'SV-51357']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

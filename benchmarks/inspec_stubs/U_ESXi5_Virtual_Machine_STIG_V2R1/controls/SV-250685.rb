control 'SV-250685' do
  title 'The system must not use independent, non-persistent disks.'
  desc 'The security issue with non-persistent disk mode is that successful attackers, with a simple shutdown or reboot, might undo or remove any traces that they were ever on the machine. To safeguard against this risk, production virtual machines should be set to use persistent disk mode; additionally, ensure activity within the VM is logged remotely on a separate server, such as a syslog server or equivalent Windows-based event collector. Without a persistent record of activity on a VM, administrators might never know whether they have been attacked or hacked.'
  desc 'check', %q(If a virtual machine does not utilize independent disks, this is not applicable

Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log on with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and locate any/all vmx files.
# find / | grep vmx

Check the ".vmx" file for the correct attribute/assignment pair. Note that the integer values of both X and Y (for the attribute scsiX:Y.mode) must be greater than or equal to 0 , depending upon the system configuration.
# grep "^scsi" <the VM's vmx file> | grep independent

Example output for the above command:
scsi2:0.mode = "independent-persistent"

If the attribute assignment is not "independent-persistent", this is a finding.
Re-enable Lockdown Mode on the host.)
  desc 'fix', %q(Configure the vmx file with the correct attribute/assignment pair. 

To edit a powered-down virtual machine's .vmx file, first remove it from vCenter Server's inventory. Manual additions to the .vmx file from ESXi will be overwritten by any registered entries stored in the vCenter Server database. Make a backup copy of the .vmx file. If the edit breaks the virtual machine, it can be rolled back to the original version of the file. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Storage. 
Right-click on the appropriate datastore and click Browse Datastore. Navigate to the folder named after the virtual machine, and locate the <virtual machine>.vmx file. Right-click the .vmx file and click Remove from inventory.

Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to the ESXi host and locate the VM's vmx file. 
# find / | grep vmx

Add the following line to the vmx file. Note that X and Y must be greater than or equal to 0 (based on the system configuration).
scsiX:Y.mode = "independent-persistent"

Re-enable Lockdown Mode on the host.

Re-register the VM with the vCenter Server:

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Storage. Right-click on the appropriate datastore and click Browse Datastore. Navigate to the folder named after the virtual machine, and locate the <virtual machine>.vmx file. Right-click the .vmx file and click Add to inventory. The Add to Inventory wizard opens. Continue to follow the wizard to add the virtual machine.)
  impact 0.7
  ref 'DPMS Target VMware ESXi Version 5 Virtual Machine'
  tag check_id: 'C-54120r799515_chk'
  tag severity: 'high'
  tag gid: 'V-250685'
  tag rid: 'SV-250685r799517_rule'
  tag stig_id: 'ESXI5-VM-000010'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54074r799516_fix'
  tag 'documentable'
  tag legacy: ['SV-51309', 'V-39451']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

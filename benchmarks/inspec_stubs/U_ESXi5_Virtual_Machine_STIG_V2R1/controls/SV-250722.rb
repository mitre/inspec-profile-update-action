control 'SV-250722' do
  title 'The system must control access to VMs through the dvfilter network APIs.'
  desc 'A VM must be configured explicitly to accept access by the dvfilter network API. This should be performed only for VMs that require the dvfilter network API. An attacker might compromise the VM by making use of this introspection channel.'
  desc 'check', %q(Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to the ESXi Shell and locate the VM's vmx file.
# find / | grep vmx

If a VM is not supposed to be protected by a product using the dvfilter API, ensure the following is not present in its VMX file: 

ethernet0.filter1.name = dv-filter1

where "ethernet0" is the network adaptor interface of the virtual machine that is to be protected, "filter1" is the number of the filter that is being used, and "dv-filter1" is the name of the particular data path kernel module that is protecting the VM. If the VM is supposed to be protected, check that the name of the data path kernel is set correctly.
# grep "^ethernet" <the VM's vmx file>

If a dvfilter is not being used, and the above command return is empty, this is not a finding.

If a dvfilter is being used, and the above command return is either empty or does not contain the correctly formatted network adaptor interface, filter number , and data path kernel module, this is a finding.

Re-enable Lockdown Mode on the host.)
  desc 'fix', %q(To edit a powered-down virtual machine's .vmx file, first remove it from vCenter Server's inventory. Manual additions to the .vmx file from ESXi will be overwritten by any registered entries stored in the vCenter Server database. Make a backup copy of the .vmx file. If the edit breaks the virtual machine, it can be rolled back to the original version of the file. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Storage. Right-click on the appropriate datastore and click Browse Datastore. Navigate to the folder named after the virtual machine, and locate the <virtual machine>.vmx file. Right-click the .vmx file and click Remove from inventory.

Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to the ESXi host and locate the VM's vmx file. 
# find / | grep vmx

Add the following to the VM's vmx file.

ethernet0.filter1.name = dv-filter1

Where "ethernet0" is the network adaptor interface of the virtual machine that is to be protected, "filter1" is the number of the filter that is being used, and "dv-filter1" is the name of the particular data path kernel module that is protecting the VM.

Re-enable Lockdown Mode on the host.

Re-register the VM with the vCenter Server. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Storage. Right-click on the appropriate datastore and click Browse Datastore. Navigate to the folder named after the virtual machine, and locate the <virtual machine>.vmx file. Right-click the .vmx file and click Add to inventory. The Add to Inventory wizard opens. Continue to follow the wizard to add the virtual machine.)
  impact 0.3
  ref 'DPMS Target VMware ESXi Version 5 Virtual Machine'
  tag check_id: 'C-54157r799626_chk'
  tag severity: 'low'
  tag gid: 'V-250722'
  tag rid: 'SV-250722r799628_rule'
  tag stig_id: 'ESXI5-VM-000051'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54111r799627_fix'
  tag 'documentable'
  tag legacy: ['V-39505', 'SV-51363']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

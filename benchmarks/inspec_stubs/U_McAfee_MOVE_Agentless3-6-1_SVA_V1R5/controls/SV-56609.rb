control 'SV-56609' do
  title 'The Virtual Machine must have VMware vShield Endpoint thin client installed and shown as protected in the vShield Manager.'
  desc 'The vShield Manager is the centralized network management component of vShield, and is installed as a virtual appliance on an ESX host in a vCenter Server environment. The vShield Manager user interface or vSphere Client plug-in is used by administrators to install, configure, and maintain vShield components. 

vShield Endpoint offloads antivirus and anti-malware agent processing to a dedicated secure virtual appliance delivered by VMware partners. Since the secure virtual appliance (unlike a guest virtual machine) does not go offline, it can continuously update antivirus signatures thereby giving uninterrupted protection to the virtual machines on the host. Also, new virtual machines (or existing virtual machines that went offline) are immediately protected with the most current antivirus signatures when they come online. vShield Endpoint installs as a hypervisor module and security virtual appliance from a third-party antivirus
vendor (VMware partners) on an ESX host. The hypervisor scans guest virtual machines from the outside, removing the need for agents in every virtual machine. This makes vShield Endpoint efficient in avoiding
resource bottlenecks while optimizing memory use.

McAfee MOVE AV Agentless requires vShield Endpoint to be installed on a virtual machine in order for the McAfee MOVE Security Virtual Appliance to protect it. If the virtual machine did not have vShield Endpoint installed, the virtual machine would not be protected from malware and viruses.'
  desc 'check', 'This STIG setting validates whether a virtual machine is protected by the McAfee MOVE Agentless 3.6.1. 

With the assistance of the System Administrator, verify the client is reporting to the endpoint solution in vShield:

a. Log in to vShield Manager 
b. Browse to Datacenters | <yourdatacenter> | <esx host of vm> | Endpoint tab.  

Virtual machines should be listed with a description of Thin Agent Enabled.

If virtual machines are not listed with a description of Thin Agent Enabled, this is a finding.'
  desc 'fix', 'If the virtual machine is not showing as a "Protected VM", install VMware Tools on the guest VM and select Custom install of VMware tools. In the vSphere Client, right-click the appropriate VM, select Guest | Install/Upgrade VMware Tools.
In the Install/Upgrade Tools dialog box, select Interactive Tools Upgrade and click OK.
Depending on the environment, select setup.exe or setup64.exe and run it as administrator.
Select Custom then click Next.
Expand VMware Device Drivers | VMCI Drivers, then select vShield Drivers | This feature will be installed on local hard drive.
Access vShield Manager to confirm the virtual machine is showing as a "Protected VM".'
  impact 0.7
  ref 'DPMS Target McAfee MOVE Agentless 3.0 Managed Virtual Machine'
  tag check_id: 'C-49405r8_chk'
  tag severity: 'high'
  tag gid: 'V-43788'
  tag rid: 'SV-56609r2_rule'
  tag stig_id: 'AV-MOVE-VM-001'
  tag gtitle: 'AV-MOVE-VM-001 Virtual Machine protected status'
  tag fix_id: 'F-49394r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

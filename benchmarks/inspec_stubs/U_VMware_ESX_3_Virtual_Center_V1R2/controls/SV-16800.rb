control 'SV-16800' do
  title 'VirtualCenter server is hosting other applications such as database servers, e-mail servers or clients, dhcp servers, web servers, etc.'
  desc 'VirtualCenter availability is critical since it controls and manages the entire virtual infrastructure. ESX Server will still function without VirtualCenter, however, management of the virtual machines is lost. VirtualCenter should be installed on a dedicated physical server or virtual machine, since running multiple applications on a VirtualCenter server poses an availability risk. Application programs such as web servers, databases, or messaging systems require a significant number of installed programs, active processes, and privileged users defined. These applications may provide a simple means by which a privileged user unintentionally introduces malicious code. Therefore, VirtualCenter servers will only run those necessary applications that are required to run the VirtualCenter service.'
  desc 'check', 'On the VirtualCenter Server perform the following.
1. Go to Start>Programs>VMware
2. All VirtualCenter components should be listed under the VMware directory. The VMware Infrastructure Management default installation includes the following components:

-	VMware VirtualCenter Server – A Windows service to manage ESX Server hosts.
-	VI Client – A client application used to connect directly to an ESX Server or indirectly to an ESX Server through a VirtualCenter Server.
-	Microsoft.NET Framework – Software that the VirtualCenter Server, the Database Upgrade wizard, and VI Client users.
-	Microsoft or Oracle Database
-	VMware license server – A Windows service allowing all VMware products to be licensed from a central pool and managed from one console.  
-	VMware Update Manager (Optional) – A VirtualCenter plugin that provides security monitoring and patching support for ESX Server hosts and virtual machines.
-	VMware Converter Enterprise for VirtualCenter (Optional) – A VirtualCenter plugin that enables the conversion of physical machines to virtual machines.
-		
3. Next go to Start> Programs> 
4. Review all the progams listed to ensure no email servers, office programs, messaging programs, etc. are installed.  If so ask the IAO/SA what they are for.  If they are unrelated to the VirtualCenter Server, this is a finding.'
  desc 'fix', 'Run only the necessary applications for VirtualCenter.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16216r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15859'
  tag rid: 'SV-16800r1_rule'
  tag stig_id: 'ESX0600'
  tag gtitle: 'VirtualCenter server is hosting other apps.'
  tag fix_id: 'F-15819r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end

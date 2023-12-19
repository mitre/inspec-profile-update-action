control 'SV-16791' do
  title 'VMware and third party applications are not supported.'
  desc 'ESX Servers require support for release version, management applications, and the guest operating systems in the virtual machine. The ESX Server runs on its own hypervisor/kernel which is supported by the VMware’s technical support. VMware and third party applications will be a supported release to ensure the release may be patched. This will ensure the ability to comply with IAVM requirements as well as access to vendor recommended and security patches.'
  desc 'check', 'There are many third party applications that may be used in conjunction with VI3. There are many VMware applications that may be used to enhance the virtualization infrastructure. These include VMware Consolidated Backup, VirtualCenter, VMotion, Hardware Availability, and Distributed Resource Scheduling.

1. Request the list of all the VMware and third party applications used in the virtualization infrastructure.  Use this list to research the support of each product.  If no list can be produced this is a finding.  

2. For all third party applications, go to the vendor’s website or request from the IAO/SA documentation verifying that the application is supported.  If the application is not supported, this is a finding.  

3. For VMware applications, look at the table and end of support dates below.  Check VMware’s website to double check the support policy in case it has been updated if you have access to the internet. The URL is http://www.vmware.com/support/policies/eos_vi.html#General  
If the VMware application is not supported, this is a finding.

VMware Consolidated Backup	General
Availability
Date 	End of Support (Security and Bug fixes)	Note
Version 1.0.3 Update 1	10/31/2007	One year after Version 1.0.3 Update 2 GA	 
Version 1.0.3	07/31/2007	10/31/2008	 
Version 1.0.2 Update 1	10/31/2007	07/31/2008	 
Version 1.0.2 	04/05/2007	10/31/2008	 
Version 1.0.1 	10/02/2006	04/05/2008	 
Version 1.0.0 	06/15/2006	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

VMware VirtualCenter, VMware Vmotion, VMware HA, and VMware DRS	General
Availability
Date 	End of Support (Security and Bug fixes)	Note
Version 2.0.2 Update 2	11/08/2007	One year after
Version 2.0.2 Update 3	 
Version 2.0.2 Update 1 	10/29/2007	11/08/2008	 
Version 2.0.2	07/19/2007	10/29/2008	 
Version 2.0.1	10/05/2006	07/19/2008	 
Version 2.0.0	06/15/2006	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

________________________________________
Version 1.4.1	09/28/2006	06/15/2010, pending no Version 1.4.2	 
Version 1.4.0	07/06/2006	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

________________________________________
Version 1.3.1 P1	03/23/2006	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

Version 1.3.1	12/22/2005	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

Version 1.3.0	09/22/2005	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

________________________________________
Version 1.2.0 P1 	02/24/2005	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

Version 1.2.0 	12/19/2004	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

________________________________________
Version 1.1.0 	08/06/2004	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

________________________________________
Version 1.0.0 	03/31/2004	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ'
  desc 'fix', 'Use only vendor supported products with the virtualization infrastructure.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16199r1_chk'
  tag severity: 'high'
  tag gid: 'V-15850'
  tag rid: 'SV-16791r1_rule'
  tag stig_id: 'ESX0510'
  tag gtitle: 'VMware applications are not supported.'
  tag fix_id: 'F-15804r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Server Administrator]', 'Information Assurance Officer', 'System Administrator']
end

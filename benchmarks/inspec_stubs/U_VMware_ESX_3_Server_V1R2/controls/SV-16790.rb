control 'SV-16790' do
  title 'ESX Server software version is not supported.'
  desc 'ESX Servers require support for release versions, management applications, and the guest operating systems in the virtual machine. The ESX Server runs on its own hypervisor/kernel which is supported by the VMware’s technical support. The ESX Server will be a supported release to ensure the release may be patched. This will ensure the ability to comply with IAVM requirements as well as access to vendor recommended and security patches.'
  desc 'check', 'On the ESX Server service console perform the following:
# esxupdate –l query

Output will look similar to this:

Installed software bundles
-----Name----        --Install Date--   --------Summary--------
3.5.0-56329          23:37:26 11/04/08  Full installation of ESX 3.5.0-56329 The line above is the ESX software version is installed.

ESX350-200802055-BG  23:49:26 11/04/08  Fix COS running Dell OM5 w/QLogic

ESX350-200803066-SG  23:50:02 11/04/08  Fix COS security bug

Check VMware’s website to double check the support policy in case it has been updated if you have access to the internet. The URL is http://www.vmware.com/support/policies/eos_vi.html#General 
Below is the support schedule for the various releases of the ESX Server.  If the esxupdate –l query return anything below 2.5.4, this is a finding.  If the query returns 3.0.0, this is a finding. For all other results, check the schedule and date for end of support to determine if this check is a finding.
VMware ESX Server	General
Availability
Date 	End of Support (Security and Bug fixes)	Note
Version 3.0.2 Update 1	10/29/2007	One year after Version 3.0.2 Update 2 GA	 
Version 3.0.2	07/31/2007	10/29/2008	 
Version 3.0.1 	10/05/2006	07/31/2008	 
Version 3.0.0 	06/15/2006	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

________________________________________
Version 2.5.5 	10/08/2007	06/15/2010, pending no Version 2.5.6 release	 
Version 2.5.4 	10/05/2006	10/08/2008	 
Version 2.5.3	04/13/2006	EOS Reached	Not covered by 
VI Support Life Cycle, see FAQ 

Version 2.5.2	09/15/2005	EOS Reached 	Not covered by 
VI Support Life Cycle, see FAQ 

Version 2.5.1	06/20/2005	EOS Reached 	Not covered by 
VI Support Life Cycle, see FAQ 

Version 2.5.0	11/29/2004	EOS Reached 	Not covered by 
VI Support Life Cycle, see FAQ'
  desc 'fix', 'Implement only VMware supported ESX Server software.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16198r1_chk'
  tag severity: 'high'
  tag gid: 'V-15849'
  tag rid: 'SV-16790r1_rule'
  tag stig_id: 'ESX0500'
  tag gtitle: 'ESX Server software version is not supported.'
  tag fix_id: 'F-15803r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Server Administrator]', 'Information Assurance Officer', 'System Administrator']
end

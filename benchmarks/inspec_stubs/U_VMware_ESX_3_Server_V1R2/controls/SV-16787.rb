control 'SV-16787' do
  title 'The ESX Server software version is not at the latest release.'
  desc 'Organizations need to stay current with all applicable ESX Server software updates that are released from VMware. Software updates are designed to update or fix problems with a computer program or its supporting data. This includes fixing bugs, replacing graphics and improving the usability or performance. ESX Servers that do not have the latest patches or updates installed have potential vulnerabilities that may be exploited.'
  desc 'check', 'On the ESX Server service console perform the following:
# esxupdate –l query
The output will look similar to the following:

Installed software bundles
-----Name----        --Install Date--   --------Summary--------
3.5.0-56329          23:37:26 11/04/08  Full installation of ESX 3.5.0-56329

ESX350-200802055-BG  23:49:26 11/04/08  Fix COS running Dell OM5 w/QLogic

ESX350-200803066-SG  23:50:02 11/04/08  Fix COS security bug

Verify the latest release is listed.  The latest release for the various software versions is listed:
Version 3.5.0 - ESX350-200712401-BG 
Version 3.0.2 Update 1 - ESX-1003359
Version 3.0.2 - ESX-1003359 (End of support is 10/29/2008)
Version 3.0.1 - ESX-1003347 (End of support is 7/31/2008)
Version 3.0.0 – Not Supported by VMware
Version 2.5.5 – Update Patch 4 (End of support 6/15/2010)
Version 2.5.4 – Update Patch 15 (End of Support is 10/8/2008)
Patches are released monthly, so check Vmware’s website to ensure new patches have not been released. The website for patch downloads is http://www.vmware.com/download/vi/.
If the latest release is not installed, this is a finding.'
  desc 'fix', 'Configure the ESX Server software with the latest release.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16194r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15846'
  tag rid: 'SV-16787r1_rule'
  tag stig_id: 'ESX0470'
  tag gtitle: 'ESX Software version is not at latest release.'
  tag fix_id: 'F-15800r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end

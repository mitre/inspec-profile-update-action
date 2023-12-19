control 'SV-55342' do
  title 'The Symantec Endpoint Protection client must have the Symantec Client State Plug-in for ePO deployed.'
  desc "All systems at DoD sites are managed by the site's HBSS ePO server for host based security. When sites choose to deploy Symantec AntiVirus products to their managed systems, these systems appear to HBSS as not protected for antivirus. When the HBSS ePO server uploads asset postures to US CYBERCOM, the systems will reflect as not having antivirus installed. In order that the Symantec status is reporting in the asset's posture within HBSS, the Symantec Client Status plug-in needs to be deployed to the Symantec-install system from the HBSS ePO server and verified to be reporting its Symantec status back to the ePO server."
  desc 'check', 'On the system to which the Symantec Endpoint Protection has been installed, find the McAfee Agent icon (red shield with white M) in the taskbar. Right click on the icon and choose "About". The dialog box which opens will reflect all installed products being managed by the McAfee Agent, as deployed from the McAfee HBSS ePO server.

Verify "Symantec Plugin" is listed as an installed product.

If the McAfee Agent "About" properties do not include the Symantec Plugin as an installed product, this is a finding.

On the client machine use the Windows Registry Editor to navigate to the following key: 
32 bit and 64 bit:
HKLM\\SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Application Plugins

If the subkey "S_SYMC_1000" does not exist, this is a finding.'
  desc 'fix', 'The fix will require the assistance of the HBSS administrator. The HBSS should deploy the Symantec Client State Plugin from the HBSS ePO server and verify the system accurately reflects its installation.'
  impact 0.7
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48895r1_chk'
  tag severity: 'high'
  tag gid: 'V-42614'
  tag rid: 'SV-55342r1_rule'
  tag stig_id: 'DTASEP006'
  tag gtitle: 'DTASEP006'
  tag fix_id: 'F-48196r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001246']
  tag nist: ['SI-3 (1)']
end

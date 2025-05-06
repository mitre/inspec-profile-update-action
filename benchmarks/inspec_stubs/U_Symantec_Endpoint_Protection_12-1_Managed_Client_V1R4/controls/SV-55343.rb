control 'SV-55343' do
  title 'The Symantec Endpoint Protection client must be verified as uploading SEP client detail to ePO.'
  desc "All systems at DoD sites are managed by the site's HBSS ePO server for host based security. When sites choose to deploy Symantec AntiVirus products to their managed systems, these systems appear to HBSS as not protected for antivirus. When the HBSS ePO server uploads asset postures to US CYBERCOM, the systems will reflect as not having antivirus installed. In order that the Symantec status be reported in the asset's posture within HBSS, the Symantec Client Status plug-in needs to be deployed to the Symantec-install system from the HBSS ePO server and verified to be reporting its Symantec status back to the ePO server."
  desc 'check', 'On the system to which the Symantec Endpoint Protection has been installed, open a Windows Explorer window and navigate to C:\\ProgramData\\McAfee\\Common Framework (on 64-bit systems) or C:\\Documents and Settings\\All Users\\Application Data\\McAfee\\Common Framework (on 32-bit systems).

Find and open with Internet Explorer the file named LastPropsSentToServer.xml.

Verify the following information in the file:

<LastUpdate> should be recent (current day)
 
SoftwareID="S_SEPEVT1100"
Setting name="ProductName">Symantec Endpoint Protection
Setting name="szProductVer">12.1.1101.401

If the LastPropsSentToServer.xml does not reflect a current <LastUpdate> date and/or does not include a section for SoftwareID="S_SEPEVT1100", this is a finding.'
  desc 'fix', 'The fix will require assistance of the HBSS administrator. The HBSS administrator should verify the McAfee Agent is successfully communicating to the ePO server. The HBSS administrator should redeploy the Symantec Client State Plugin and verify it uploads the Symantec client state correctly to the ePO server.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48896r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42615'
  tag rid: 'SV-55343r1_rule'
  tag stig_id: 'DTASEP007'
  tag gtitle: 'DTASEP007'
  tag fix_id: 'F-48197r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001246']
  tag nist: ['SI-3 (1)']
end

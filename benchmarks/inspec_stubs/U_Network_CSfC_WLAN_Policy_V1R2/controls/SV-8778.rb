control 'SV-8778' do
  title 'All wireless/mobile systems (including associated peripheral devices, operating system, applications, network/PC connection methods, and services) must be approved by the approval authority prior to installation and use for processing DoD information.'
  desc 'Unauthorized wireless systems expose DoD networks to attack. The DAA and appropriate commanders must be aware of all wireless systems used at the site. DAAs should ensure a risk assessment for each system including associated services and peripherals, is conducted before approving. Accept risks only when needed to meet mission requirements.'
  desc 'check', 'Detailed Policy Requirements: For CMDs deployed under an Interim Security Configuration Guide (ISCG) or the DoD CIO’s 6 April 2011 memorandum, Use of Commercial Mobile Devices (CMD) in the Department of Defense (DoD), the approval authority is the Component CIO. The site must have an Interim Authority To Test (IATT) issued by the Component CIO.

For all other wireless devices and systems the Designated Approval Authority (DAA) must approve the wireless device or system. 

Detailed Check Procedures:
Work with the site POC to verify documentation. Performed with WIR0016 (equipment list).

For CMD systems without a STIG, verify the site has an approved IATT. Mark as a finding if a valid IATT is not available or is not signed by the Component CIO.

For all other wireless devices or systems, complete the following:
1. Request copies of written DAA approval documentation. Any of the following documents meets this requirement as proof of compliance:
- The DIACAP IA Implementation Plan must show the wireless system as part of the network diagram or list the system/equipment as being part of the network.
- DAA approval letter or other document. The document must list the system or equipment and date its use is approved.
The DAA approval letter or SSP may be a general statement of approval rather than list each device. 

2. Verify DAA approval for type of device used, such as wireless connection services, peripherals, and applications. 

Mark as a finding for any of the following reasons:
- Wireless systems, devices, services, or accessories are in use but DAA approval letter(s) do not exist.
- If, in the judgment of the reviewer, configuration differs significantly from that approved by the DAA approval letter.

Note: The DAA approval for the wireless system does not need to be documented separately from other DAA approval documents for the site network, as long as the approval documents list the wireless system. For example, if a site network ATO lists the wireless system, the ATO meets the requirements of this check.

For Secure Mobile Environment Portable Electronic Device (SME PED), the following applies:
- An ATO or an IATO has been signed by the DAA prior to the connection of the unclassified Sensa server to the NIPRNet.
- Classified Connection Approval Office (CCAO) approval has been obtained prior to the connection of the classified Sensa server to the SIPRNet.

Note: The intent of this check is to ensure the DAA has approved the use of the wireless system being reviewed at the site. This approval can be documented in several ways. The most common is the SSP for the site includes the wireless system and the DAA has signed the SSP. If the command uses an enterprise wide SSP including the wireless system being reviewed and the SSP applies to site being reviewed, then the requirement has been met.'
  desc 'fix', 'Obtain DAA approval (documented by memo or SSP) prior to wireless systems being installed and used. For CMD systems without a STIG, obtain an IATT prior to wireless systems being installed and used.'
  impact 0.7
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-3890r6_chk'
  tag severity: 'high'
  tag gid: 'V-8283'
  tag rid: 'SV-8778r6_rule'
  tag stig_id: 'WIR0005'
  tag gtitle: 'Wireless/mobile systems authorized prior to use'
  tag fix_id: 'F-19194r3_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Designated Approving Authority', 'Information Assurance Manager']
  tag ia_controls: 'ECWN-1'
end

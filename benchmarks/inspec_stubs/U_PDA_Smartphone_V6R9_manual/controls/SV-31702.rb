control 'SV-31702' do
  title 'PDA and Smartphones that are connected to DoD Windows computers via a USB connection must be compliant with requirements.'
  desc 'PDAs with flash memory can introduce malware to a PC when they are connected for provisioning of the PDA or to transfer data between the PC and PDA, particularly if the PDA is seen by the PC as a mass storage device and autorun in enabled.'
  desc 'check', 'NOTE:  This check applies to any handheld mobile device (PDA, non-email Windows Mobile or Palm OS PDA, iPod, bar code scanner, RFID scanner, cell phone, etc.) that is connected to a DoD Windows PC for the purpose of provisioning or transferring data between the PC and mobile device.  This check does not apply to BlackBerrys, Windows Mobile smartphones used for email, and SME PEDs.  Requirements for these devices are found in the appropriate STIG for the device.  

These requirements do not apply to:
-PDAs that are never connected to Windows PCs.
-PDAs connected to stand-alone DoD Windows computers that are not connected to a DoD network.
-PCMCIA cards with flash memory used to store user data.  For example, many new broadband wireless modems have this capability.  (NOTE:  encryption of data stored on the flash memory may be required by Assistant Secretary of Defense for Networks and Information Integration/DoD Chief Information Officer Memorandum, “Encryption of Sensitive Unclassified Data at Rest on Mobile Computing Devices and Removable Storage,” July 3, 2007.)
-PCMCIA cards with non-user addressable ROM flash memory.

Detailed Policy Requirements: 

PDAs and smartphones will not be connected to DoD Windows computers via a USB connection unless the following conditions are met:

- The DoD Windows computer utilizes the DoD Host Based Security System (HBSS) with the Device Control Module (DCM). Configuration requirements are found in CTO 10-004A.

-Autorun is disabled on the Windows PC.

Check Procedures:

Interview the IAO and smartphone administrator. 

Check the following on sample (use 3-4 devices as a random sample) PCs and smartphones:

- Verify the site has implemented HBSS with DCM on computers used to connect BlackBerrys. Have the Windows reviewer assist in determining that HBSS with DCM is installed (ususally verified during a Windows Workstation review)..

- Verify Autorun is disabled (ususally verified during a Windows Workstation review).'
  desc 'fix', 'Windows PCs used to connect to smartphones will be configured so they are compliant with requirements.'
  impact 0.5
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-22309r1_chk'
  tag severity: 'medium'
  tag gid: 'V-18625'
  tag rid: 'SV-31702r1_rule'
  tag stig_id: 'WIR-MOS-PDA-032'
  tag gtitle: 'PDA and smartphone connection to PC via USB'
  tag fix_id: 'F-28611r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECWN-1'
end

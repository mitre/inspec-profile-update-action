control 'SV-31703' do
  title 'Removable memory cards (e.g., MicroSD) must use a FIPS 140-2 validated encryption module to bind the card to a particular device such that the data on the card is not readable on any other device.'
  desc 'Memory card used to transfer files between PCs and PDAs is a migration path for the spread of malware on DoD computers and handheld devices.  These risks are mitigated by the requirements listed in this check.'
  desc 'check', 'Note: Removable flash media is defined as media that is readily accessible by the user and does not require additional tools to disassemble the device or remove screws to gain access.

Note: This check applies to any handheld mobile device (PDA, non-email Windows Mobile or Palm OS PDA, bar code scanner, RFID scanner, cell phone, etc.) that is connected to a DoD Windows PC for the purpose of provisioning or transferring data between the PC and mobile device. This check does not apply to BlackBerrys, Windows Mobile smartphones used for email, and SME PEDs. Requirements for these devices are found in the appropriate Checklist for the device.

Check Procedures:

Interview the IAO to determine if the site uses removable memory cards in site managed handheld PDAs. 

If Yes,
-Determine if FIPS 140-2 data encryption has been implemented on the memory cards. Ask the IAO for FIPS certificate or search for it on the NIST web site. 
-Determine if the removable data storage media card is bound to the PED such that it may not be read by any other PED or computer. Procedures will vary, depending on system vendor. Ask the IAO for system technical documentation showing this capability and how to configure. 
-Determine if the security policy on the PDA is configured to deny the use of removable data storage media on site managed PEDs (if this capability is available). Procedures will vary, depending on system vendor. Ask the IAO for system technical documentation showing this capability and how to configure it. 
-Determine if the site uses a removable data storage memory card to load files on site PDAs for the purpose of provisioning the PDA. If yes, verify the memory card used for provisioning has either been provided by the PDA vendor or loaded with provisioning files from a non-NIPRNet computer.
Mark as a finding if the requirements for compliance are not met.'
  desc 'fix', 'Comply with requirement'
  impact 0.5
  ref 'DPMS Target RFID'
  tag check_id: 'C-22664r1_chk'
  tag severity: 'medium'
  tag gid: 'V-18856'
  tag rid: 'SV-31703r1_rule'
  tag stig_id: 'WIR-MOS-PDA-033'
  tag gtitle: 'Removable flash media and FIPS 140-2 encryption'
  tag fix_id: 'F-19400r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECWN-1'
end

control 'SV-31699' do
  title 'DoD-licensed anti-malware software will be installed on all wireless clients (e.g., PDAs and smartphones) and non-wireless PDAs.'
  desc 'Security risks inherent to wireless technology usage can be minimized with security measures such current anti-virus updates.'
  desc 'check', 'Detailed Policy Requirements:

DoD-licensed anti-malware software must be installed on all wireless clients (e.g., PDAs and smartphones) and non-wireless PDAs and is kept up-to-date with the most recent virus signatures every 14 days or less. 

Note:  This requirement does not apply to any handheld PDA that is not used to connect to the internet or a DoD computer or network.  It does not apply to handheld bar-code or RFID scanners that are connected to DoD computers to download scanned data (handheld is used only as a bar-code / RFID scanner).  In addition, this requirement does not apply to phones that only have the capability for voice calls only, including wireless VoIP and Unlicensed Mobile Access (UMA) (no data, Internet connections other than for voice calls over wireless VoIP and UMA).

Check Procedures:

Verify laptop computers, PDAs, and smartphones are protected by anti-virus software.

For PDAs and cell phones, inspect a sample of the devices (3 – 4 devices).  Verify the software is:
o Configured to scan upon startup (once daily) (or at least scan once every week) or the user trained to scan at least once per week.
o Configured to automatically update at least every 14 days or the user trained to manually update once every two weeks. 
o Enabled for Web browser download protection.
o If DoD approved antivirus products (e.g. downloaded from the JTF GNO antivirus portal) are not available for the wireless device, sites must select commercial products which are from major vendors with preference given to products tested or already used by other DoD organizations.
o The DAA must give written approval of this product.

Mark as a finding if any of the following are true:  
o No antivirus software is installed; update procedures are not configured or used; or the software is not configured IAW the Wireless STIG policy.'
  desc 'fix', 'The IAO will ensure DoD licensed anti-virus software is installed on all wireless clients (e.g., laptops, PDAs, and cellular telephones) and the software is configured in accordance with the Desktop Application STIG and is kept up-to-date with the most recent virus signatures every 14 days or less.'
  impact 0.5
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-11769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14275'
  tag rid: 'SV-31699r1_rule'
  tag stig_id: 'WIR-MOS-PDA-039'
  tag gtitle: 'Use anti-virus software'
  tag fix_id: 'F-3427r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECWN-1'
end

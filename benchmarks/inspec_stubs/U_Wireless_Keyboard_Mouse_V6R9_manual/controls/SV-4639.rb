control 'SV-4639' do
  title 'If a wireless keyboard or mouse is used with any site computers, then it must follow security requirements.'
  desc 'The use of unauthorized wireless keyboards and mice can compromise DoD computers, networks, and data.  The receiver for a wireless keyboard/mouse provides a wireless port on the computer that could be attacked by a hacker.  Wireless keyboard transmissions can be intercepted by a hacker and easily viewed if required security is not used.'
  desc 'check', 'Detailed Policy Requirements:

If a wireless keyboard or mouse is used with any site workstations, the following requirements must be followed:

- If WLAN is used for the wireless connection, assign “WLAN Client” asset posture in VMS to the workstation (or PDA) asset and complete WLAN checks assigned to the workstation (or PDA).
- If Bluetooth or some other wireless technology is used for the wireless connection, assign “Bluetooth” asset posture in VMS to the workstation (or PDA) asset and complete Bluetooth checks assigned to the workstation(or PDA).

Check Procedures:

Verify the appropriate VMS wireless posture has been assigned to the workstation asset and the appropriate checks have been completed.  Mark as a finding if the requirements are not met.

NOTE:  Currently, no wireless keyboards or mice meet these requirements.  If  the wireless mouse/keyboard is using a proprietary RF protocol (i.e., not Bluetooth or 802.11), then apply the Bluetooth checks.'
  desc 'fix', 'Comply with requirement.'
  impact 0.5
  ref 'DPMS Target Wireless Peripheral'
  tag check_id: 'C-4009r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4639'
  tag rid: 'SV-4639r1_rule'
  tag stig_id: 'WIR0535'
  tag gtitle: 'Wireless keyboards and mice'
  tag fix_id: 'F-19256r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECWN-1'
end

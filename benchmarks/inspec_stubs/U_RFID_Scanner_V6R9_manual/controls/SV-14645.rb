control 'SV-14645' do
  title 'If a wireless connection (e.g. WLAN, Bluetooth) is used between the RFID scanner and RFID workstation, security requirements must be followed.'
  desc 'Sensitive data stored on the RFID scanner and transmitted to the workstation could be compromised.'
  desc 'check', 'Detail Policy Requirements:
If a wireless connection (e.g. WLAN, Bluetooth) is used between the RFID scanner and RFID workstation, the following requirements must be followed:

- If WLAN is used for the wireless connection, assign “WLAN Client” asset posture in VMS to the workstation (or PDA) asset and complete WLAN checks assigned to the workstation (or PDA).

- If Bluetooth or some other wireless technology is used for the wireless connection, assign “Bluetooth” asset posture in VMS to the workstation (or PDA) asset and complete Bluetooth checks assigned to the workstation(or PDA).

Check Procedures:
Verify that the appropriate VMS wireless posture has been assigned to the RFID workstation (or PDA) asset and the appropriate checks have been completed.  Mark as a finding if the requirement has not been met.'
  desc 'fix', 'Comply with the security requirements associated with the technology enabling wireless communication between the RFID scanner and RFID computing infrastructure.'
  impact 0.3
  ref 'DPMS Target RFID'
  tag check_id: 'C-11509r1_chk'
  tag severity: 'low'
  tag gid: 'V-14034'
  tag rid: 'SV-14645r1_rule'
  tag stig_id: 'WIR0500'
  tag gtitle: 'Wireless RFID workstation / scanner compliant'
  tag fix_id: 'F-13509r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECWN-1'
end

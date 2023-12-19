control 'SV-95071' do
  title 'Samsung Android 8 with Knox must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39a'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has a USB mass storage mode and whether it has been disabled.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Disable USB Media Player" check box in the "Android Restrictions" rule. 
2. Verify the "Disable USB Media Player" check box is selected. 

Note: Disabling USB Media Player will also disable USB MTP, USB mass storage, and USB vendor protocol (Smart Switch, KIES).

On the Samsung Android 8 with Knox device, connect the device to a PC USB connection.

Note: Do not use a DoD network-managed PC for this test!

On the PC:
Verify the device is not shown in the PC finder.

If the MDM console "Disable USB Media Player" is not set to disable USB mass storage mode or with the Samsung Android 8 with Knox device, it is shown as a USB mass storage device on the PC, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to disable USB mass storage mode.

On the MDM console, select the "Disable USB Media Player" check box in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80039r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80367'
  tag rid: 'SV-95071r1_rule'
  tag stig_id: 'KNOX-08-015000'
  tag gtitle: 'PP-MDF-301210'
  tag fix_id: 'F-87173r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

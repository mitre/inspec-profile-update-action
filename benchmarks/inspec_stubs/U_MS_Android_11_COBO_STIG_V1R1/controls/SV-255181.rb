control 'SV-255181' do
  title 'Microsoft Android 11 must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39a'
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the mobile device has a USB mass storage mode and whether it has been disabled. 

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open "User restrictions on parent".
2. Verify that "Disallow usb file transfer" is toggled to "On".

On the Microsoft Android 11 device:
1. Plug a USB cable into Android 11 device and connect to a non-DOD network-managed PC. 
2. Go to Settings >> Connected devices >> USB.
3. Ensure "No data transfer" is selected.

If the EMM console device policy is not set to disable USB mass storage mode or on the Android 11 device, the device policy is not set to disable USB mass storage mode, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to disable USB mass storage mode.

On the EMM console:
1. Open "User restrictions on parent".
2. Toggle "Disallow usb file transfer".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58794r870679_chk'
  tag severity: 'medium'
  tag gid: 'V-255181'
  tag rid: 'SV-255181r870680_rule'
  tag stig_id: 'MSFT-11-003500'
  tag gtitle: 'PP-MDF-301210'
  tag fix_id: 'F-58738r869405_fix'
  tag 'documentable'
  tag cci: ['CCI-002546']
  tag nist: ['SC-41']
end

control 'SV-228291' do
  title 'The Google Android Pie must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39a'
  desc 'check', 'Review Google Android device configuration settings to determine if the mobile device has a USB mass storage mode and whether it has been disabled. 

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console, do the following:

1. Open Device Restrictions.
2. Open Restrictions Settings.
3. Ensure "Disallow usb file transfer" is selected.

On the Android Pie device, do the following:

1. Plug in USB cable into Android Pie device and connect to a non-DoD network-managed PC. 
2. Go to Settings >> Connected devices >> USB
3. Ensure No data transfer is selected.

If the MDM console device policy is not set to disable USB mass storage mode or on the Android Pie device, the device policy is not set to disable USB mass storage mode, this is a finding.'
  desc 'fix', 'Configure the Google Android device to disable USB mass storage mode.

On the MDM console:

1. Open Device Restrictions.
2. Open Restrictions Settings.
3. Select "Disallow usb file transfer".'
  impact 0.5
  ref 'DPMS Target Google Android 9-x'
  tag check_id: 'C-30524r494940_chk'
  tag severity: 'medium'
  tag gid: 'V-228291'
  tag rid: 'SV-228291r617456_rule'
  tag stig_id: 'GOOG-09-003500'
  tag gtitle: 'PP-MDF-301210'
  tag fix_id: 'F-30509r494941_fix'
  tag 'documentable'
  tag legacy: ['SV-106435', 'V-97331']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

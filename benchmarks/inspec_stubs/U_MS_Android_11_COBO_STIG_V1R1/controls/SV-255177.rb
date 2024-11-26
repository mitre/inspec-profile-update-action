control 'SV-255177' do
  title 'Microsoft Android 11 must be configured to enable encryption for data at rest on removable storage media or alternately, the use of removable storage media must be disabled.'
  desc "The Microsoft Android device must ensure the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #21, #47f"
  desc 'check', 'Review Microsoft Android device settings to determine if the Microsoft Android device has disabled use of removable storage media.

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open "Set user restrictions".
2. Verify that "Disallow usb file transfer" is toggled to "On".
3. Verify that "Disallow mount physical media" is toggled to "On".

On the Microsoft Android 11 device:
1. Insert SD card and/or attach a USB storage device.
2. Validate that use of either is unavailable for storing data.

If the use of removable storage has not been disabled, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to disable use of removable storage media.

On the EMM console:
1. Open "Set user restrictions".
2. Toggle "Disallow usb file transfer" to "On".
3. Toggle "Disallow mount physical media" to "On".'
  impact 0.7
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58790r870669_chk'
  tag severity: 'high'
  tag gid: 'V-255177'
  tag rid: 'SV-255177r870671_rule'
  tag stig_id: 'MSFT-11-002000'
  tag gtitle: 'PP-MDF-301140'
  tag fix_id: 'F-58734r870670_fix'
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002235']
  tag nist: ['SC-28', 'AC-6 (10)']
end

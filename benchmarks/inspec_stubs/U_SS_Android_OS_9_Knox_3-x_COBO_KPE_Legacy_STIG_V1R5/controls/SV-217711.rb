control 'SV-217711' do
  title 'Samsung Android must be configured to not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review device configuration settings to confirm that passwords with two repeating or sequential characters are prevented. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, do the following: 
1. For the device, in the "Knox password constraint" group, verify that "maximum sequential characters" is "2" or less. 
2. For the device, in the "Knox password constraint" group, verify that "maximum sequential numbers" is "2" or less. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Lock screen". 
3. Tap "Screen lock type". 
4. Enter current password. 
5. Tap "Password". 
6. Verify that passwords with two or more sequential characters or numbers are not accepted. 

If on the MDM console "maximum sequential characters" or "maximum sequential numbers" is more than "2", or on the Samsung Android device a password with two or more sequential characters or numbers is accepted, this is a finding.'
  desc 'fix', 'Configure Samsung Android to prevent passwords from containing more than two repeating or sequential characters. 

On the MDM console, for the device, in the "Knox password constraints" group: 
1. Set "maximum sequential characters" to "2". 
2. Set "maximum sequential numbers" to "2".'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE Legacy'
  tag check_id: 'C-18929r362281_chk'
  tag severity: 'low'
  tag gid: 'V-217711'
  tag rid: 'SV-217711r388482_rule'
  tag stig_id: 'KNOX-09-000395'
  tag gtitle: 'PP-MDF-301020'
  tag fix_id: 'F-18927r362282_fix'
  tag 'documentable'
  tag legacy: ['SV-103669', 'V-93583']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

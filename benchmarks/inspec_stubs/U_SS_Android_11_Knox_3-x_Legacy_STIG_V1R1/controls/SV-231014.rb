control 'SV-231014' do
  title 'Samsung Android must be configured to not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'This requirement is not applicable if the password quality is set to Numeric (complex) or better.

Review Samsung Android configuration settings to determine if the mobile device is prohibiting passwords with more than two repeating or sequential characters.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device password section, verify the "maximum sequential numbers" is set to "2". 

On the Samsung Android device: 
1. Open Settings. 
2. Tap "Lock screen". 
3. Tap "Screen lock type". 
4. Enter current password. 
5. Tap "Password". 
6. Verify that passwords with two or more sequential numbers are not accepted. 

If on the management tool "maximum sequential numbers" is more than "2", or on the Samsung Android device a password with two or more sequential numbers is accepted, this is a finding.'
  desc 'fix', 'This requirement is not applicable if the password quality is set to Numeric (complex), or better.

Configure Samsung Android to prevent passwords from containing more than two repeating or sequential characters.

On the management tool, in the device password section, set the "maximum sequential numbers" to "2".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33944r592656_chk'
  tag severity: 'medium'
  tag gid: 'V-231014'
  tag rid: 'SV-231014r608683_rule'
  tag stig_id: 'KNOX-11-000400'
  tag gtitle: 'PP-MDF-301020'
  tag fix_id: 'F-33917r592657_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-242507' do
  title 'Zebra Android 10 must be configured to not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk. The numeric (complex) setting allows the use of a numeric-only keyboard for passwords and enforces the repeating or sequential characters limitation.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review Zebra Android 10 device configuration settings to determine if the mobile device is prohibiting passwords with more than two repeating or sequential characters.

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Verify the password quality is set to "Numeric (Complex)".

On the Zebra Android 10 device:
1. Open Settings >> Security >> Screen lock.
2. Enter current password.
3. Tap "Password".
4. Verify Password complexity requirements are listed: Ascending, descending, or repeated sequence of digits is not allowed.

If the MDM console device policy is set to a password with more than two repeating or sequential characters or on the Zebra Android 10 device, the device policy is set to a password with more than two repeating or sequential characters, this is a finding.

Note: Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these will cause the user to select a complex password, which is not required by the STIG.'
  desc 'fix', 'Configure the Zebra Android 10 device to prevent passwords from containing more than two repeating or sequential characters.

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Set password quality to "Numeric (Complex)".

Note: Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these will cause the user to select a complex password, which is not required by the STIG.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45782r714364_chk'
  tag severity: 'medium'
  tag gid: 'V-242507'
  tag rid: 'SV-242507r714366_rule'
  tag stig_id: 'ZEBR-10-000200'
  tag gtitle: 'PP-MDF-301020'
  tag fix_id: 'F-45739r714365_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

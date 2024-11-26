control 'SV-228606' do
  title 'Google Android 11 must be configured to not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk. The numeric (complex) setting allows the use of a numeric only keyboard for passwords and enforces the repeating or sequential characters limitation.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review Google Android device configuration settings to determine if the mobile device is prohibiting passwords with more than two repeating or sequential characters.

This validation procedure is performed on both the EMM Administration Console and the Android 11 device.

On the EMM console, do the following:
1. Open "Password constraints".
2. Select "Personal Profile".
3. Verify that quality is set to "Numeric (Complex)".

On the Android 11 device, do the following:
1. Open Settings >> Security >> Screen lock.
2. Enter current password.
3. Tap "Password".
4. Try to enter a new PIN or Password with repeating numbers or characters.
5. Verify Password complexity requirements are listed: Ascending, descending, or repeated sequence of digits is not allowed.

If the EMM console device policy is set to a password with more than two repeating or sequential characters or on the Android 11 device, the device policy is set to a password with more than two repeating or sequential characters, this is a finding.

NOTE: Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these selections will cause the user to select a complex password, which is not required by the STIG.'
  desc 'fix', 'Configure the Google Android 11 device to prevent passwords from containing more than two repeating or sequential characters.

On the EMM console:
1. Open "Password constraints".
2. Select "Personal Profile".
3. Set password quality to "Numeric (Complex)".

NOTE: Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these selections will cause the user to select a complex password, which is not required by the STIG.'
  impact 0.5
  ref 'DPMS Target Google Android 11 COPE'
  tag check_id: 'C-30841r505815_chk'
  tag severity: 'medium'
  tag gid: 'V-228606'
  tag rid: 'SV-228606r619923_rule'
  tag stig_id: 'GOOG-11-000200'
  tag gtitle: 'PP-MDF-301020'
  tag fix_id: 'F-30818r505816_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

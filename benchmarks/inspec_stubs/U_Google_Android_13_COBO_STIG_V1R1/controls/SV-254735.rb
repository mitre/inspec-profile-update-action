control 'SV-254735' do
  title 'Google Android 13 must be configured to not allow passwords that include more than four repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review managed Google Android 13 device configuration settings to determine if the mobile device is prohibiting passwords with more than four repeating or sequential characters.

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 13 device.

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Password constraints".
3. Verify that quality is set to "Numeric (Complex)" or higher.

COPE:

1. Open "Lock screen" settings.
2. Open "Password constraints".
3. Select "Personal Profile".
4. Verify that quality is set to "Numeric (Complex)" or higher.
____________________________

On the managed Google Android 13 device:

COBO and COPE:

1. Open Settings >> Security >> Screen lock.
2. Enter current password.
3. Select "PIN".
4. Try to enter a new PIN with repeating numbers.
5. Verify Password complexity requirements are listed: Ascending, descending, or repeated sequence of digits is not allowed.

If the EMM console device policy is set to a password with more than two repeating or sequential characters or on the managed Google Android 13 device, the device policy is set to a password with more than two repeating or sequential characters, this is a finding.

Note: Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these selections will cause the user to select a complex password, which is not required by the STIG.'
  desc 'fix', 'Configure the Google Android 13 device to prevent passwords from containing more than four repeating or sequential characters.

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Password constraints".
3. Set password quality to "Numeric (Complex)".

COPE:

1. Open "Password constraints".
2. Select "Personal Profile".
3. Set password quality to "Numeric (Complex)".

Note: Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these selections will cause the user to select a complex password, which is not required by the STIG.'
  impact 0.5
  ref 'DPMS Target Google Android 13 COBO'
  tag check_id: 'C-58346r862402_chk'
  tag severity: 'medium'
  tag gid: 'V-254735'
  tag rid: 'SV-254735r862404_rule'
  tag stig_id: 'GOOG-13-006100'
  tag gtitle: 'PP-MDF-323025'
  tag fix_id: 'F-58292r862403_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

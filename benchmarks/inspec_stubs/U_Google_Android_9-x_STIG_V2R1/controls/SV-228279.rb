control 'SV-228279' do
  title 'The Google Android Pie must be configured to not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', %q(Review Google Android device configuration settings to determine if the mobile device is prohibiting passwords with more than two repeating or sequential characters.  

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console, do the following:

On the MDM console:
1.  Open password requirements
2.  Open device password section
3.  Ensure the password quality is set to "Numeric (Complex)"

On the Android Pie device, do the following:

1.  Open Settings >> Security & location >> Screen lock
2.  Enter current password
3.  Tap on "Password"
4.  Verify Password complexity requirements are listed: Ascending, descending, or repeated sequence of digits isn't allowed

If the MDM console device policy is set to a password with more than two repeating or sequential characters or, on the Android Pie device, the device policy is set to a password with more than two repeating or sequential characters, this is a finding.

Note: Alphabetic, Alphanumeric, and Complex are also acceptable selections but these selections will cause the user to select a complex password, which is not required by the STIG.)
  desc 'fix', 'Configure the Google Android device to prevent passwords from containing more than two repeating or sequential characters.

On the MDM console:
1.  Open password requirements
2.  Open device password section
3.  Set password quality to "Numeric (Complex)"

Note: Alphabetic, Alphanumeric, and Complex are also acceptable selections but these selections will cause the user to select a complex password, which is not required by the STIG.'
  impact 0.5
  ref 'DPMS Target Google Android 9-x'
  tag check_id: 'C-30512r494904_chk'
  tag severity: 'medium'
  tag gid: 'V-228279'
  tag rid: 'SV-228279r494906_rule'
  tag stig_id: 'GOOG-09-000200'
  tag gtitle: 'PP-MDF-301020'
  tag fix_id: 'F-30497r494905_fix'
  tag 'documentable'
  tag legacy: ['SV-106411', 'V-97307']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-235063' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review Honeywell Android device configuration settings to determine if the mobile device is prohibiting passwords with more than two repeating or sequential characters. 

This validation procedure is performed on both the MDM Administration console and the Android Pie device. 

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Ensure the password quality is set to "Numeric (Complex)".

On the Honeywell Android Pie device:
1. Open Settings >> Security & location >> Screen lock.
2. Enter current password.
3. Tap on "Password".
4. Verify Password complexity requirements are listed: Must contain at least 1 letter.

If the MDM console device policy is set to a password with more than two repeating or sequential characters or on the Honeywell Android Pie device, the device policy is set to a password with more than two repeating or sequential characters, this is a finding.

NOTE: Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these selections will cause the user to select a complex password, which is not required by the STIG.'
  desc 'fix', 'Configure the Honeywell Android device to prevent passwords from containing more than two repeating or sequential characters.

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Set password quality to "Numeric (Complex)".

NOTE: Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these selections will cause the user to select a complex password, which is not required by the STIG.'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38282r623204_chk'
  tag severity: 'medium'
  tag gid: 'V-235063'
  tag rid: 'SV-235063r626527_rule'
  tag stig_id: 'HONW-09-000200'
  tag gtitle: 'PP-MDF-301020'
  tag fix_id: 'F-38245r623205_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

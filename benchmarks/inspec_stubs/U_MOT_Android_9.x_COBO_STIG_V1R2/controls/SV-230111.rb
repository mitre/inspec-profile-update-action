control 'SV-230111' do
  title 'The Motorola Android Pie must be configured to not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review Motorola Android device configuration settings to determine if the mobile device is prohibiting passwords with more than two repeating or sequential characters. 

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console: 
1. Open password requirements.
2. Open device password section.
3. Verify the password quality is set to "Complex".

On the Android Pie device: 
1. Open Settings >> Security & location >> Screen lock.
2. Enter current password.
3. Tap on "Password".
4. Verify Password complexity requirements are listed: must contain at least one letter, one numeric digit, one special symbol.

If the MDM console device policy is set to a password with more than two repeating or sequential characters, or on the Android Pie device, the device policy is set to a password with more than two repeating or sequential characters, this is a finding.'
  desc 'fix', 'Configure the Motorola Android device to prevent passwords from containing more than two repeating or sequential characters.

On the MDM console: 
1. Open password requirements.
2. Open device password section.
3. Set password quality to "Complex".'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COBO STIG'
  tag check_id: 'C-58119r859706_chk'
  tag severity: 'medium'
  tag gid: 'V-230111'
  tag rid: 'SV-230111r859708_rule'
  tag stig_id: 'MOTO-09-000200'
  tag gtitle: 'GOOG-09-000200'
  tag fix_id: 'F-58068r859707_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

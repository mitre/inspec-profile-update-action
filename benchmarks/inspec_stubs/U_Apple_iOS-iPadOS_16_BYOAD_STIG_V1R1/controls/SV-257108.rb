control 'SV-257108' do
  title 'Apple iOS/iPadOS 16 must be configured to not allow passwords that include more than four repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review configuration settings to confirm simple passcodes are not allowed.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool:
- For User Enrollment, verify a Password profile has been installed on Managed mobile devices.
- For Device Enrollment, verify "Allow simple value" is unchecked in the Passcode profile.

On the iPhone and iPad: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "VPN & Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the password policy.
5. Tap "Restrictions".
6a. For User Enrollment, verify a Passcode profile is present.
6b. For Device Enrollment, Tap "Passcode". Verify "Simple passcodes allowed" is set to "No".

For User Enrollment, if a Password profile is not installed, this is a finding.

For Device Enrollment, if "Allow simple value" is checked in the Apple iOS/iPadOS management tool or the password policy on the iPhone and iPad does not have "Simple passcodes allowed" set to "No", this is a finding.'
  desc 'fix', 'Install a configuration profile to disallow more than four sequential or repeating numbers or letters in the device unlock password. 

Note: For User Enrollment, this requirement is met automatically if a Password profile is installed.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60793r904222_chk'
  tag severity: 'medium'
  tag gid: 'V-257108'
  tag rid: 'SV-257108r904224_rule'
  tag stig_id: 'AIOS-16-706600'
  tag gtitle: 'PP-MDF-333025'
  tag fix_id: 'F-60734r904223_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

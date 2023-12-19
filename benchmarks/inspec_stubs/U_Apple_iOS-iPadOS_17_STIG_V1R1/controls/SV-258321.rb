control 'SV-258321' do
  title 'Apple iOS/iPadOS 17 must be configured to not allow passwords that include more than four repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review configuration settings to confirm simple passcodes are not allowed.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow simple value" is unchecked. Alternatively, verify the text "<key>allowSimple</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "VPN & Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the password policy.
5. Tap "Restrictions".
6. Tap "Passcode".
7. Verify "Simple passcodes allowed" is set to "No".

If "Allow simple value" is checked in the Apple iOS/iPadOS management tool, "<key>allowSimple</key> <true/>" appears in the Configuration Profile, or the password policy on the iPhone and iPad does not have "Simple passcodes allowed" set to "No", this is a finding.'
  desc 'fix', 'Install a configuration profile to disallow more than four sequential or repeating numbers or letters in the device unlock password.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62062r927644_chk'
  tag severity: 'medium'
  tag gid: 'V-258321'
  tag rid: 'SV-258321r927646_rule'
  tag stig_id: 'AIOS-17-006600'
  tag gtitle: 'PP-MDF-333025'
  tag fix_id: 'F-61986r927645_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end

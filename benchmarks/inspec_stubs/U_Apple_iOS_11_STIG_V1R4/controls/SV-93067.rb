control 'SV-93067' do
  title 'Apple iOS must not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review configuration settings to confirm that simple passcodes are not allowed.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify the "Allow simple value" is unchecked. Alternatively, verify the text "<key>allowSimple</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the password policy.
5. Tap "Restrictions".
6. Tap "Passcode".
7. Verify "Simple passcodes allowed" is set to "No".

If "Allow simple value" is checked in the Apple iOS management tool, "<key>allowSimple</key> <true/>" appears in the Configuration Profile, or the password policy on the Apple iOS device from the Apple iOS management tool does not have "Simple passcodes allowed" set to "No", this is a finding.'
  desc 'fix', 'Install a configuration profile to disallow more than two sequential or repeating numbers or letters in the device unlock password.'
  impact 0.3
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77923r1_chk'
  tag severity: 'low'
  tag gid: 'V-78361'
  tag rid: 'SV-93067r1_rule'
  tag stig_id: 'AIOS-11-000200'
  tag gtitle: 'PP-MDF-301020'
  tag fix_id: 'F-85093r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

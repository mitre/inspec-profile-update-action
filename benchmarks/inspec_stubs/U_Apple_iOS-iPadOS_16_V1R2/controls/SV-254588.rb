control 'SV-254588' do
  title 'Apple iOS/iPadOS 16 must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review configuration settings to confirm the minimum passcode length is six or more characters.

This procedure is performed in the Apple iOS/iPadOS management tool and on the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Management tool, verify the "Minimum passcode length" value is set to six or greater.

Alternatively, verify the text "<key>minLength</key> <integer>6</integer>" appears in the configuration profile (.mobileconfig file). It also is acceptable for the integer value to be greater than six.

On the iPhone and iPad:
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the password policy.
5. Tap "Restrictions".
6. Tap "Passcode".
7. Verify "Minimum length" is listed as "six or greater".

If the "Minimum passcode length" is less than six characters in the iOS management tool, "<key>minLength</key> " has an integer value of less than six, or the password policy on the iPhone and iPad from the Apple iOS/iPadOS management tool does not list "Minimum length" of six or fewer, this is a finding.'
  desc 'fix', 'Install a configuration profile to enforce a minimum passcode length value of six or greater.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58199r862018_chk'
  tag severity: 'medium'
  tag gid: 'V-254588'
  tag rid: 'SV-254588r862020_rule'
  tag stig_id: 'AIOS-16-006500'
  tag gtitle: 'PP-MDF-323024'
  tag fix_id: 'F-58145r862019_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

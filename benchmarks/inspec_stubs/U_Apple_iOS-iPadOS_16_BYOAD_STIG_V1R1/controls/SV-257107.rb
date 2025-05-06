control 'SV-257107' do
  title 'Apple iOS/iPadOS 16 must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review configuration settings to confirm the minimum passcode length is six or more characters.

This procedure is performed in the Apple iOS/iPadOS management tool and on the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Management tool, for User Enrollment, verify a Passcode profile has been sent to managed mobile devices. For Device Enrollment, verify the Passcode profile has "Minimum passcode length" value set to six or greater.

On the iPhone and iPad:
1. Open the Settings app. 
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the password policy.
5. Tap "Restrictions".
6a. For User Enrollment, verify a Passcode profile is present.
6b. For Device Enrollment, Tap "Passcode". Verify "Minimum length" is listed as "six or greater".

For User Enrollment, if a Password profile is not installed, this is a finding.

For Device Enrollment, if the "Minimum passcode length" is less than six characters in the iOS management tool or the password policy on the iPhone and iPad from the Apple iOS/iPadOS management tool does not list "Minimum length" of six or greater, this is a finding.'
  desc 'fix', 'Install a configuration profile to enforce a minimum passcode length value of six or greater.

For User Enrollment, when a Passcode profile is installed on the mobile device, the password length is automatically set to six characters. 

For Device enrollment, the password length must be set to six characters in the Passcode profile.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60792r904219_chk'
  tag severity: 'medium'
  tag gid: 'V-257107'
  tag rid: 'SV-257107r904221_rule'
  tag stig_id: 'AIOS-16-706500'
  tag gtitle: 'PP-MDF-333024'
  tag fix_id: 'F-60733r904220_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

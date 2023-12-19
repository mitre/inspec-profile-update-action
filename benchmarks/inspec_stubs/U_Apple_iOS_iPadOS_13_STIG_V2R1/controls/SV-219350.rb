control 'SV-219350' do
  title 'Apple iOS/iPadOS must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or less gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review configuration settings to confirm that consecutive failed authentication attempts is set to 10 or fewer.

This procedure is performed in the Apple iOS/iPadOS management tool and on the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Management tool, verify the "Maximum number of failed attempts" value is set to 10 or fewer.

Alternatively, verify the text "<key>maxFailedAttempts</key> <integer>10</integer>" appears in the configuration profile (.mobileconfig file). It also is acceptable for the integer value to be less than 10.

On the iPhone and iPad: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the password policy.
5. Tap "Restrictions".
6. Tap "Passcode".
7. Verify "Max failed attempts" is listed as "10" or fewer.

If the "Maximum number of failed attempts" is more than 10 in the iOS management tool, "<key>maxFailedAttempts</key> " has an integer value of more than 10, or the password policy on the iPhone and iPad does not list "Max failed attempts" of 10 or fewer, this is a finding.'
  desc 'fix', 'Install a configuration profile to allow only 10 or fewer consecutive failed authentication attempts.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21075r547567_chk'
  tag severity: 'low'
  tag gid: 'V-219350'
  tag rid: 'SV-219350r604137_rule'
  tag stig_id: 'AIOS-13-000400'
  tag gtitle: 'PP-MDF-301050'
  tag fix_id: 'F-21074r547568_fix'
  tag 'documentable'
  tag legacy: ['SV-106529', 'V-97425']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end

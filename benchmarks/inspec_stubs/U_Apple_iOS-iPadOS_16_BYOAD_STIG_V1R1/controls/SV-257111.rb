control 'SV-257111' do
  title 'Apple iOS/iPadOS 16 must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or less gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review configuration settings to confirm consecutive failed authentication attempts is set to 10 or fewer.

This procedure is performed in the Apple iOS/iPadOS management tool and on the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

For User Enrollment, check a sample of user phones to verify compliance:
1. Open the Settings app.
2. Tap "Face ID & Passcode".
3. When prompted, enter Passcode.
4. Scroll down and verify "Erase Data" is turned on.
Note: The number of failed attempts is automatically set to "10".

For Device Enrollment:
In the Management tool, verify the "Maximum number of failed attempts" value is set to "10" or fewer.

On the iPhone and iPad: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the password policy.
5. Tap "Restrictions".
6. Tap "Passcode".
7. Verify "Max failed attempts" is listed as "10" or fewer.

For User Enrollment, if "Erase Data" is not turned on for sample devices, this is a finding.

For Device Enrollment, if the "Maximum number of failed attempts" is more than "10" in the iOS management tool or the password policy on the iPhone and iPad does not list "Max failed attempts" of "10" or fewer, this is a finding.'
  desc 'fix', 'For User Enrollment, this is a User-Based Enforcement (UBE) control. The device user must configure setting on their personal phone.
1. Open the Settings app.
2. Tap "Face ID & Passcode".
3. When prompted, enter Passcode.
4. Scroll down and turn on "Erase Data".
Note: The number of failed attempts is automatically set to "10".

For Device Enrollment, install a configuration profile to allow only "10" or fewer consecutive failed authentication attempts.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60796r904231_chk'
  tag severity: 'medium'
  tag gid: 'V-257111'
  tag rid: 'SV-257111r904233_rule'
  tag stig_id: 'AIOS-16-706900'
  tag gtitle: 'PP-MDF-333040'
  tag fix_id: 'F-60737r904232_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end

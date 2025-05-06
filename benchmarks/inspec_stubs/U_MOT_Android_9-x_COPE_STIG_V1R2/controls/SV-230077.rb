control 'SV-230077' do
  title 'The Motorola Android Pie must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting in device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review Motorola Android device configuration settings to determine if the mobile device is enforcing a minimum password length of six characters.

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console: 
1. Open password requirements.
2. Open device password section.
3. Verify the minimum password length is set to "6" characters.

On the Android Pie device: 
1. Open Settings >> Security & location >> Screen lock.
2. Enter current password.
3. Tap on "Password".
4. Verify Password length listed is at least "6".

If the device password length is not set to six characters or more on the MDM console or the Android Pie device, this is a finding.'
  desc 'fix', 'Configure the Motorola Android device to enforce a minimum password length of six characters.

On the MDM console: 
1. Open password requirements.
2. Open device password section.
3. Enter the number of characters as "6".'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-58151r859802_chk'
  tag severity: 'medium'
  tag gid: 'V-230077'
  tag rid: 'SV-230077r859804_rule'
  tag stig_id: 'MOTO-09-000100'
  tag gtitle: 'GOOG-09-000100'
  tag fix_id: 'F-58100r859803_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

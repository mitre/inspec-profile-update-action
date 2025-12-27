control 'SV-242506' do
  title 'Zebra Android 10 must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review Zebra Android 10 device configuration settings to determine if the mobile device is enforcing a minimum password length of six characters.

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Verify the minimum password length is set to six characters.

On the Zebra Android 10 device:
1. Open Settings >> Security >> Screen lock.
2. Enter current password.
3. Tap "Password".
4. Verify Password length listed is at least "6".

If the device password length is not set to six characters or more on the MDM console or on the Zebra Android 10 device, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to enforce a minimum password length of six characters.

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Enter the number of characters as "6".'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45781r714361_chk'
  tag severity: 'medium'
  tag gid: 'V-242506'
  tag rid: 'SV-242506r714363_rule'
  tag stig_id: 'ZEBR-10-000100'
  tag gtitle: 'PP-MDF-301010'
  tag fix_id: 'F-45738r714362_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

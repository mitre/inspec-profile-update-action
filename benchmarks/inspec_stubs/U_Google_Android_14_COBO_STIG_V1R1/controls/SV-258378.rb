control 'SV-258378' do
  title 'Google Android 14 must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting in device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review managed Google Android 14 device configuration settings to determine if the mobile device is enforcing a minimum password length of six characters.

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 14 device. 

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Password constraints".
3. Open "Minimum password quality".
4. Verify Numeric Complex, Alphabetic, Alphanumeric, or Complex is selected.
5. Open "Minimum password length".
6. Verify "6" is set for number of characters.

COPE:

1. Open "Lock screen" settings.
2. Open "Password constraints".
3. Select "Personal Profile".
4. Verify "Minimum password quality" is set to Numeric Complex, Alphabetic, Alphanumeric, or Complex.
5. Open "Minimum password length".
6. Verify the number of characters is set to "6" or higher.
_____________________________

On the managed Google Android 14 device:

COBO and COPE:

1. Open Settings >> Security >> Screen lock.
2. Enter current password.
3. Tap "Pin or Password".
4. Verify Password length required is at least "6".

If the device password length is not set to six characters or more on EMM console or on the managed Google Android 14 device, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to enforce a minimum password length of six characters.

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Password constraints".
3. Open "Minimum password quality".
4. Choose Numeric Complex, Alphabetic, Alphanumeric, or Complex.
5. Open "Minimum password length".
6. Enter in the number of characters as "6".

COPE:

1. Open "Lock screen" settings.
2. Open "Password constraints".
3. Select "Personal Profile".
4. Open "Minimum password quality".
5. Choose Numeric Complex, Alphabetic, Alphanumeric, or Complex.
6. Open "Minimum password length".
7. Enter in the number of characters as "6".'
  impact 0.5
  ref 'DPMS Target Google Android 14 COBO'
  tag check_id: 'C-62119r928157_chk'
  tag severity: 'medium'
  tag gid: 'V-258378'
  tag rid: 'SV-258378r928159_rule'
  tag stig_id: 'GOOG-14-006000'
  tag gtitle: 'PP-MDF-333024'
  tag fix_id: 'F-62043r928158_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

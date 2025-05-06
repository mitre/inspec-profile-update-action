control 'SV-250419' do
  title 'Google Android 12 must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review managed Google Android 12 device configuration settings to determine if the mobile device is enforcing a minimum password length of six characters.

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 12 device. 

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Password constraints".
3. Open "Minimum password quality".
4. Verify that Numeric Complex, Alphabetic, Alphanumeric, or Complex is selected.
5. Open "Minimum password length".
6. Verify that "6" is set for number of characters.

COPE:

1. Open "Lock screen" settings.
2. Open "Password constraints".
3. Select "Personal Profile".
4. Verify that "Minimum password quality" is set to Numeric Complex, Alphabetic, Alphanumeric, or Complex.
5. Open "Minimum password length".
6. Verify the number of characters is set to "6" or higher.
_____________________________

On the managed Google Android 12 device:

COBO and COPE:

1. Open Settings >> Security >> Screen lock.
2. Enter current password.
3. Tap "Pin or Password".
4. Verify Password length required is at least "6".

If the device password length is not set to six characters or more on EMM console or on the managed Google Android 12 device, this is a finding.'
  desc 'fix', 'Configure the Google Android 12 device to enforce a minimum password length of six characters.

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
  ref 'DPMS Target Google Android 12 COPE'
  tag check_id: 'C-53854r802622_chk'
  tag severity: 'medium'
  tag gid: 'V-250419'
  tag rid: 'SV-250419r802624_rule'
  tag stig_id: 'GOOG-12-006000'
  tag gtitle: 'PP-MDF-323024'
  tag fix_id: 'F-53808r802623_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

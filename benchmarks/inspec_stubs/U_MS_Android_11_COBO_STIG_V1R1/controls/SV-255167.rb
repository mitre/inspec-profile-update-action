control 'SV-255167' do
  title 'Microsoft Android 11 must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the mobile device is enforcing a minimum password length of six characters.

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open "Password constraints".
2. Select "Personal Profile".
3. Open "Minimum password quality".
4. Check that Numeric Complex, Alphabetic, Alphanumeric, or Complex is selected.
5. Verify that "Minimum password length" is "6".

On the Microsoft Android 11 device:
1. Open Settings >> Security >> Screen lock.
2. Enter current password.
3. Tap "Password or PIN".
4. Verify Password length listed is at least "6".

If the device password length is not set to six characters or more on EMM console or on the Android 11 device, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to enforce a minimum password length of six characters.

On the EMM console:
1. Open "Password constraints".
2. Select "Personal Profile".
3. Open "Minimum password quality".
4. Choose Numeric Complex, Alphabetic, Alphanumeric, or Complex.
5. Open "Minimum password length".
6. Enter in the number of characters as "6".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58780r870641_chk'
  tag severity: 'medium'
  tag gid: 'V-255167'
  tag rid: 'SV-255167r870642_rule'
  tag stig_id: 'MSFT-11-000100'
  tag gtitle: 'PP-MDF-301010'
  tag fix_id: 'F-58724r869363_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

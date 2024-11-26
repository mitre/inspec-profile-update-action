control 'SV-258476' do
  title 'Google Android 13 must be configured to enforce a minimum password length of six characters and not allow passwords that include more than four repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

'
  desc 'check', 'Review managed Google Android 13 device configuration settings to determine if the mobile device is enforcing a high password quality for the device and standard DOD password complexity rules for the Work Profile (at least six-character length and prevent passwords from containing more than four repeating or sequential characters).

1. Verify the device password configuration:

On the EMM console:
a. Open "Lock screen" settings.
b. Open "Set required password complexity on parent".
c. Verify "High" is selected.

2. Verify the Work Profile password configuration:

On the EMM console (for the work profile):
1. Open "Lock screen" settings.
2. Open "Password constraints".
3. Open "Minimum password quality".
4. Verify Numeric Complex, Alphabetic, Alphanumeric, or Complex is selected.
5. Open "Minimum password length".
6. Verify "6" is set for number of characters.

If the device password quality is not set to High or the Work Profile password length is not set to six characters or the password quality is not set as required, this is a finding.

Note: verifying the OneLock configuration is not required because the use of OneLock is optional.'
  desc 'fix', 'Configure the Google Android 13 device to enforce high password quality for the device and standard DOD password complexity rules for the Work Profile (at least six-character length and prevent passwords from containing more than four repeating or sequential characters). In addition, enable OneLock so the user only must enter their device password to unlock the Work Profile. Note: enabling OneLock is optional and is a two-step process: configuration on the EMM and configuration by the user on the phone. If OneLock is not used, the user will always need to enter separate passwords to unlock the device and to unlock the Work Profile.

1. Set the password on the whole device:
Set device password complexity to "HIGH" (requires (at minimum) an eight numeric character password, or six alphabetic character password, or a six alphanumeric character password)

On the EMM console:
a. Open "Lock screen" settings.
b. Open "Set required password complexity on parent".
c. Select "High".

2. Set DOD password for the Work Profile.

On the EMM console:
a. Open "Lock screen" settings.
b. Open "Password constraints".
c. Open "Minimum password quality".
d. Choose Numeric Complex, Alphabetic, Alphanumeric, or Complex.
e. Open "Minimum password length".
f. Enter in the number of characters as "6".

3. Enable OneLock on the EMM.

On the MDM console:
a. Disable the following Android API: "DISALLOW_UNIFIED_PASSWORD". The exact procedure will depend on the EMM product.
Note: this control may be called "Require separate challenge".

4. Train users to implement OneLock with the following User Based Enforcement (UBE): procedure:

a. Open Settings >> Security & privacy >> More security settings.
b. Enable "Use one lock".'
  impact 0.5
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62216r929242_chk'
  tag severity: 'medium'
  tag gid: 'V-258476'
  tag rid: 'SV-258476r929244_rule'
  tag stig_id: 'GOOG-13-706000'
  tag gtitle: 'PP-MDF-333024'
  tag fix_id: 'F-62125r929243_fix'
  tag satisfies: ['PP-MDF-333024', 'PP-MDF-333025\n\nSFR ID: FMT_SMF_EXT.1.1 #1a']
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

control 'SV-241193' do
  title 'Samsung Android must be configured to not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review Samsung Android configuration settings to determine if the mobile device is prohibiting passwords with more than two repeating or sequential characters.

This validation procedure is performed on both the management tool and the Samsung Android device.

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

****

Method #1: Require Numeric(Complex) password.

On the management tool, in the device password requirements section, verify that "minimum password quality" is set to "Numeric (Complex)".

On the Samsung Android device, do the following:
1. Open Settings >> Lock screen >> Screen lock type.
2. Enter current password.
3. Tap "PIN".
4. Enter a password with an invalid sequence and verify that text "Consecutive or repeating numbers are not allowed" is displayed above the PIN entry.

If on the management tool the "minimum password quality" is not set to "Numeric (Complex)", or on the Samsung Android device the text "Consecutive or repeating numbers are not allowed" is not displayed, this is a finding.

****

Method #2: Require Numeric password with KPE password constraints.

On the management tool, do the following:
1. In the device password requirements section, verify the "minimum password quality" is set to "Numeric".
2. In the KPE device password section, verify that "maximum sequential characters" is "2" or less. 
3. In the KPE device password section, verify that "maximum sequential numbers" is "2" or less. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Lock screen". 
3. Tap "Screen lock type". 
4. Enter current password. 
5. Tap "Password". 
6. Verify that passwords with two or more sequential numbers are not accepted. 

If on the management tool "minimum password quality" is not set to "Numeric" or "maximum sequential characters" or "maximum sequential numbers" is more than "2", or on the Samsung Android device a password with two or more sequential characters or numbers is accepted, this is a finding.

****

Note: Alphabetic, Alphanumeric, and Complex are also acceptable selections but these selections will cause the user to select a complex password, which is not required by the STIG.'
  desc 'fix', 'Configure Samsung Android to prevent passwords from containing more than two repeating or sequential characters.

Do one of the following:
- Method #1: Require Numeric(Complex) password.
- Method #2: Require Numeric password with KPE password constraints.

****

Method #1: Require Numeric(Complex) password.

On the management tool, in the device password requirements section, set the "minimum password quality" to "Numeric (Complex)".

****

Method #2: Require Numeric password with KPE password constraints.

On the management tool, do the following:
1. In the device password requirements section, set the "minimum password quality" to "Numeric".
2. In the KPE device password section, set the "maximum sequential numbers" to "2". 

****

Note: Alphabetic, Alphanumeric, and Complex are also acceptable selections but will cause the user to select a complex password, which is not required by the STIG.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44469r680218_chk'
  tag severity: 'medium'
  tag gid: 'V-241193'
  tag rid: 'SV-241193r680220_rule'
  tag stig_id: 'KNOX-10-000200'
  tag gtitle: 'PP-MDF-301020'
  tag fix_id: 'F-44428r680219_fix'
  tag 'documentable'
  tag legacy: ['V-99915', 'SV-109019']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

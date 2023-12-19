control 'SV-251805' do
  title 'Samsung Android must be configured to not allow passwords that include more than four repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disallowing passwords containing more than four repeating or sequential characters.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device password policies, verify "minimum password quality" is set to "Numeric(Complex)" or better.

On the Samsung Android device: 
1. Open Settings >> Lock screen >> Screen lock type. 
2. Enter current password. 
3. Tap "PIN". 
4. Verify that PINS with more than four repeating or sequential numbers are not accepted.

If on the management tool "minimum password quality" is not set to "Numeric(Complex)" or better, or on the Samsung Android device a password with more than four repeating or sequential numbers is accepted, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disallow passwords containing more than four repeating or sequential characters.

On the management tool, in the device password policies, set "minimum password quality" to "Numeric(Complex)" or better.

If your management tool does not support "Numeric(Complex)" but does support "Numeric", KPE can be used to achieve STIG compliance. In this case, configure this policy with value "Numeric" and use an additional KPE policy (innately by the management tool or via KSP) "Maximum Numeric Sequence Length" with value "4".'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55265r814169_chk'
  tag severity: 'medium'
  tag gid: 'V-251805'
  tag rid: 'SV-251805r814171_rule'
  tag stig_id: 'KNOX-12-110030'
  tag gtitle: 'PP-MDF-323010'
  tag fix_id: 'F-55219r814170_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

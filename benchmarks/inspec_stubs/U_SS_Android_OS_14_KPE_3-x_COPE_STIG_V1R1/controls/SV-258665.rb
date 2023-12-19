control 'SV-258665' do
  title 'Samsung Android must be configured to not allow passwords that include more than four repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disallowing passwords containing more than four repeating or sequential characters.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device password policies, verify "minimum password quality" is set to "Numeric(Complex)" or better.

On the Samsung Android device: 
1. Open Settings >> Lock screen >> Screen lock type. 
2. Enter current password. 
3. Tap "PIN". 
4. Verify PINs with more than four repeating or sequential numbers are not accepted.

If on the management tool "minimum password quality" is not set to "Numeric(Complex)" or better, or on the Samsung Android device a password with more than four repeating or sequential numbers is accepted, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disallow passwords containing more than four repeating or sequential characters.

On the management tool, in the device password policies, set "minimum password quality" to "Numeric(Complex)" or better.

If the management tool does not support "Numeric(Complex)" but does support "Numeric", Knox Platform for Enterprise (KPE) can be used to achieve STIG compliance. In this case, configure this policy with value "Numeric" and use an additional KPE policy (innately by the management tool or via KSP) "Maximum Numeric Sequence Length" with value "4".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62405r931193_chk'
  tag severity: 'medium'
  tag gid: 'V-258665'
  tag rid: 'SV-258665r931195_rule'
  tag stig_id: 'KNOX-14-210030'
  tag gtitle: 'PP-MDF-333025'
  tag fix_id: 'F-62314r931194_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end

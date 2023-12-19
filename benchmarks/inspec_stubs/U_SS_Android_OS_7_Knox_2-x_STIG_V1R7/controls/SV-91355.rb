control 'SV-91355' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Configure minimum Container password complexity.'
  desc 'Authentication mechanisms other than a Password Authentication Factor often provide convenience to users, but many of these mechanisms have known vulnerabilities. Configuring a minimum password complexity mitigates the risk associated with a weak authentication factor.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is enforcing minimum Container password complexity.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following: 
1. Ask the MDM administrator to display the "Minimum Password Complexity" setting in the "Android Knox Container >> Container Password Restrictions" rule. 
2. Verify the value of the setting is PIN. (see Note)

On the Samsung Android 7 with Knox device, do the following: 
1. Open the Knox Container.
2. Select "Knox Settings".
3. Select "Lock type".
4. Enter current password.
5. Verify "Pattern" are grayed out and cannot be selected.

If the MDM console "Minimum Password Complexity" is not set to "Alphanumeric" or on the Samsung Android 7 with Knox device, the user is able to select "Pattern" from the "Lock Type" setting, this is a finding.

Note: This configuration setting will allow users to implement fingerprint unlock for the container, which is approved for use. However, this approval does not extend to fingerprint unlock for the Samsung device or any other DoD mobile device.

Note: Some MDM consoles may display “Numeric” and “Numeric-Complex” instead of “PIN”. Either selection is acceptable but “Numeric-Complex” is recommended. Alphabetic, Alphanumeric, and Complex are also acceptable selections but these selections will cause the user to select a complex password, which is not required by the STIG.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enforce minimum Container password complexity.

On the MDM console, set the "Minimum Password Complexity" value to "PIN" in the "Android Knox Container >> Container Password Restrictions" rule.   

Note: Some MDM consoles may display “Numeric” and “Numeric-Complex” instead of “PIN”. Either selection is acceptable but “Numeric-Complex” is recommended. Some MDM consoles may display “Numeric” and “Numeric-Complex” instead of “PIN”. Either selection is acceptable but “Numeric-Complex” is recommended. Alphabetic, Alphanumeric, and Complex are also acceptable selections but these selections will cause the user to select a complex password, which is not required by the STIG.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76329r2_chk'
  tag severity: 'medium'
  tag gid: 'V-76659'
  tag rid: 'SV-91355r2_rule'
  tag stig_id: 'KNOX-07-914500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83353r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-95029' do
  title 'Samsung Android 8 with Knox must implement the management setting: Configure minimum CONTAINER password complexity.'
  desc 'Authentication mechanisms other than a Password Authentication Factor often provide convenience to users, but many of these mechanisms have known vulnerabilities. Configuring a minimum password complexity mitigates the risk associated with a weak authentication factor.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing minimum CONTAINER password complexity.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following: 
1. Ask the MDM Administrator to display the "Minimum Password Complexity" setting in the "Android Knox CONTAINER >> CONTAINER Password Restrictions" rule. 
2. Verify the value of the setting is "PIN" (see note).

On the Samsung Android 8 with Knox device, do the following: 
1. Open the Knox CONTAINER.
2. Select "Workspace settings".
3. Select "Lock type".
4. Enter current password.
5. Verify "Pattern" is grayed out and cannot be selected.

If the MDM console "Minimum Password Complexity" is not set to "PIN" or on the Samsung Android 8 with Knox device, the user is able to select "Pattern" from the "Lock Type" setting, this is a finding. 

Note: This configuration setting will allow users to implement fingerprint unlock for the CONTAINER, which is approved for use. However, this approval does not extend to fingerprint unlock for the Samsung device or any other DoD mobile device.

Note: Some MDM consoles may display “Numeric” and “Numeric-Complex” instead of “PIN”. Either selection is acceptable but “Numeric-Complex” is recommended. Alphabetic, Alphanumeric, and Complex are also acceptable selections but these selections will cause the user to select a complex password, which is not required by the STIG.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce minimum CONTAINER password complexity.

On the MDM console, set the "Minimum Password Complexity" value to "PIN" in the "Android Knox CONTAINER >> CONTAINER Password Restrictions" rule.  

Note: Some MDM consoles may display “Numeric” and “Numeric-Complex” instead of “PIN”. Either selection is acceptable but “Numeric-Complex” is recommended. Alphabetic, Alphanumeric, and Complex are also acceptable selections, but these selections will cause the user to select a complex password, which is not required by the STIG.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79997r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80325'
  tag rid: 'SV-95029r2_rule'
  tag stig_id: 'KNOX-08-008900'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87131r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

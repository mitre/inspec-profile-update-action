control 'SV-253876' do
  title 'The SchUseStrongCrypto registry value must be set.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered.

This requirement applies only to applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications must leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec. FIPS 140-2 approved TLS versions must be enabled, and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 defines the approved TLS versions for government applications.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', '1. Access the Tanium Server, Tanium Module Server, and Tanium SQL Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to the following and confirm the setting "SchUseStrongCrypto" is present and configured as follows: 

Navigate to: HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Microsoft >> .NETFramework >> v4.0.xxxxx (the subversion number may vary, but it is a 4.0 version; example: 4.0.30319) for Tanium Application Server.

Navigate to: HKEY_LOCAL_MACHINE >> SOFTWARE >> Microsoft >> .NETFramework >> v4.0.xxxxx (the subversion number may vary, but it is a 4.0 version; example: 4.0.30319) for Tanium SQL Server.

Navigate to: HKEY_LOCAL_MACHINE >> SOFTWARE >> Microsoft >> .NETFramework >> v4.0.xxxxx (the subversion number may vary, but it is a 4.0 version; example: 4.0.30319) for Tanium Module Server.

Name: SchUseStrongCrypto
Type: REG_DWORD
Data: 0x0000001 (hex)

If the value for "SchUseStrongCrypto " is not set to "0x00000001" (hex) and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.'
  desc 'fix', '1. Access the Tanium Server, Tanium Module Server, and Tanium SQL Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Use the following locations for steps 5-13.

Navigate to: HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Microsoft >> .NETFramework >> v4.0.xxxxx (the subversion number may vary, but it is a 4.0 version; example: 4.0.30319) for Tanium Application Server.

Navigate to: HKEY_LOCAL_MACHINE >> SOFTWARE >> Microsoft >> .NETFramework >> v4.0.xxxxx (the subversion number may vary, but it is a 4.0 version; example: 4.0.30319) for Tanium SQL Server.

Navigate to: HKEY_LOCAL_MACHINE >> SOFTWARE >> Microsoft >> .NETFramework >> v4.0.xxxxx (the subversion number may vary, but it is a 4.0 version; example: 4.0.30319) for Tanium Module Server.

5. Right-click in the right window pane.

6. Select: New >> DWORD (32-bit) Value.

7. In the "Name" field, enter "SchUseStrongCrypto".

8. Press "Enter".

9. Right-click the newly created "Name".

10. Select "Modify...".

11. Enter "1" in "Value data:".

12. Ensure that under "Base", the "Hexadecimal" radio button is selected.

13. Click "OK".'
  impact 0.7
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57328r842654_chk'
  tag severity: 'high'
  tag gid: 'V-253876'
  tag rid: 'SV-253876r850269_rule'
  tag stig_id: 'TANS-SV-000101'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-57279r842655_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

control 'SV-253877' do
  title 'The SSLCipherSuite registry value must be set.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered.

This requirement applies only to applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications must leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec. FIPS 140-2 approved TLS versions must be enabled, and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 defines the approved TLS versions for government applications.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to: HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Name: SSLCipherSuite
Type: String
Value:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSAAES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK

If the String "SSLCipherSuite" does not exist with the appropriate list values, this is a finding.'
  desc 'fix', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to: HKEY_LOCAL_MACHINE >> Software >> Wow6432Node >> Tanium >> Tanium Server.

5. Right-click in the right window pane.

6. Select: New >> String Value.

7. In the "Name" field, enter "SSLCipherSuite".

8. Press "Enter".

9. Right-click the newly created "Name".

10. Select "Modify".

11. Add the following: ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSAAES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK

12. Click "OK".'
  impact 0.7
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57329r842657_chk'
  tag severity: 'high'
  tag gid: 'V-253877'
  tag rid: 'SV-253877r850269_rule'
  tag stig_id: 'TANS-SV-000107'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-57280r842658_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

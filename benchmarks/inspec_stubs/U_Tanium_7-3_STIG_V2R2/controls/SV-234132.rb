control 'SV-234132' do
  title 'The Tanium application must be configured to communicate using TLS 1.2 Strict Only.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered.

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec. FIPS 140-2 approved TLS versions must be enabled, and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 defines the approved TLS versions for government applications.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', %q(Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Access the server's registry by typing: "regedit".

Press "Enter".

Navigate to: HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Name: SSLCipherSuite
Type: String
Value:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSAAES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK

If the String "SSLCipherSuite" does not exist with the appropriate list values, this is a finding.)
  desc 'fix', %q(Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Access the server's registry by typing: "regedit".

Press "Enter".

Navigate to: HKEY_LOCAL_MACHINE >> Software >> Wow6432Node >> Tanium >> Tanium Server.

Right-click in the right window pane.

Select: New >> String Value.

In the "Name" field, enter "SSLCipherSuite".

Press "Enter".

Right-click on the newly created "Name".

Select "Modify...".

Add the following: ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSAAES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK

Click "OK".)
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37317r610896_chk'
  tag severity: 'medium'
  tag gid: 'V-234132'
  tag rid: 'SV-234132r612749_rule'
  tag stig_id: 'TANS-SV-000107'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-37282r610897_fix'
  tag 'documentable'
  tag legacy: ['SV-102337', 'V-92235']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

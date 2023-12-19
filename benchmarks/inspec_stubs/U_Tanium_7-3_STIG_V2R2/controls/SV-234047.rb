control 'SV-234047' do
  title 'The Tanium application must retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. This is typically determined and performed at the operating system-level, but in some instances it may be at the application-level.

Regardless of where the session lock is determined and implemented, once invoked the session lock shall remain in place until the user re-authenticates. No other system or application activity aside from re-authentication shall unlock the system.'
  desc 'check', 'Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Run regedit as Administrator.

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Validate the value for REG_DWORD "ForceSOAPSSLClientCert" is set to "1".

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Validate the following keys exist and are configured:
REG_SZ "ClientCertificateAuthField"

For example: 
X509v3 Subject Alternative Name.

REG_SZ "ClientCertificateAuthRegex"

For example-DoD:
.*\\:\\s*([^@]+)@.*
$Note: This regedit should be valid for any Subject Alternative Name entry.

REG_SZ "ClientCertificateAuth"
Note: This registry value defines which certificate file to use for authentication.

For example:
C:\\Program Files\\Tanium\\Tanium Server\\dod.pem

REG_SZ "cac_ldap_server_url"

Note: This registry value requires that Tanium validate every CAC/PIV authentication attempt with AD to determine the state of the account that is logging in. It must use the syntax similar to LDAP://<AD instance FQDN>

If the value for REG_DWORD "ForceSOAPSSLClientCert" is not set to "1" and the remaining registry values are not configured, this is a finding.'
  desc 'fix', 'Use the vendor documentation titled "Reference: Smartcard authentication" to implement correct configuration settings for this requirement. If assistance is required, contact the Tanium Technical Account Manager (TAM).

Vendor documentation can be downloaded from the following URL: https://docs.tanium.com/platform_install/platform_install/reference_smart_card_authentication.html.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37232r610641_chk'
  tag severity: 'medium'
  tag gid: 'V-234047'
  tag rid: 'SV-234047r612749_rule'
  tag stig_id: 'TANS-CN-000001'
  tag gtitle: 'SRG-APP-000002'
  tag fix_id: 'F-37197r610642_fix'
  tag 'documentable'
  tag legacy: ['SV-102167', 'V-92065']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end

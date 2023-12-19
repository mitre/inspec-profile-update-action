control 'SV-93323' do
  title 'Common Access Card (CAC)-based authentication must be enforced and enabled on the Tanium Server for network and local access with privileged and non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following.

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This not only meets a common requirement in the Federal space but adds a critical layer of security to the user authentication process.

'
  desc 'check', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Run regedit as Administrator.

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server

Validate the value for REG_DWORD "ForceSOAPSSLClientCert" is set to "1".

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server

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
Note: This registry value requires that Tanium validate every CAC/PIV authentication attempt with AD to determine the state of the account that is logging on. It must use the syntax similar to LDAP://<AD instance FQDN>

If the value for REG_DWORD "ForceSOAPSSLClientCert" is not set to "1" and the remaining registry values are not configured, this is a finding.'
  desc 'fix', 'Use the vendor documentation titled "Reference: Smart card authentication" to implement correct configuration settings for this requirement. If assistance is required, contact the Tanium Technical Account Manager (TAM).

Vendor documentation can be downloaded from the following URL: https://docs.tanium.com/platform_install/platform_install/reference_smart_card_authentication.html.'
  impact 0.7
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78187r1_chk'
  tag severity: 'high'
  tag gid: 'V-78617'
  tag rid: 'SV-93323r1_rule'
  tag stig_id: 'TANS-CN-000010'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-85353r1_fix'
  tag satisfies: ['SRG-APP-000149', 'SRG-APP-000151']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000767']
  tag nist: ['IA-2 (1)', 'IA-2 (3)']
end

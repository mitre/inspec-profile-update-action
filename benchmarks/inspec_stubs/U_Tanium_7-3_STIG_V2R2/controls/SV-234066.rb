control 'SV-234066' do
  title 'Common Access Card (CAC)-based authentication must be enabled and enforced on the Tanium Server for all access and all accounts.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

'
  desc 'check', 'Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Run regedit as Administrator.

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Validate the value for REG_DWORD "ForceSOAPSSLClientCert" is set to "1".

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Validate the following keys exist and are configured:

REG_SZ "ClientCertificateAuthField"

For example:

X509v3 Subject Alternative Name

REG_SZ "ClientCertificateAuthRegex"

For example-DoD:

.*\\:\\s*([^@]+)@.*

$Note: This regedit should be valid for any Subject Alternative Name entry.

REG_SZ "ClientCertificateAuth"

Note: This registry value defines which certificate file to use for authentication.

For example:

C:\\Program Files\\Tanium\\Tanium Server\\dod.pem

REG_SZ "cac_ldap_server_url"

Note: This registry value requires that Tanium validate every CAC/PIV authentication attempt with AD to determine the state of the account that is logging on. It must use the syntax similar to LDAP://<AD instance FQDN>.

If the value for REG_DWORD "ForceSOAPSSLClientCert" is not set to "1" and the remaining registry values are not configured, this is a finding.'
  desc 'fix', 'Use the vendor documentation titled "Reference: Smart card authentication" to implement correct configuration settings for this requirement.

If assistance is required, contact the Tanium Technical Account Manager (TAM).

Vendor documentation can be downloaded from the following URL:

https://docs.tanium.com/platform_install/platform_install/reference_smart_card_authentication.html.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37251r610698_chk'
  tag severity: 'medium'
  tag gid: 'V-234066'
  tag rid: 'SV-234066r612749_rule'
  tag stig_id: 'TANS-CN-000027'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-37216r610699_fix'
  tag satisfies: ['SRG-APP-000148', 'SRG-APP-000005', 'SRG-APP-000150', 'SRG-APP-000152', 'SRG-APP-000080', 'SRG-APP-000156', 'SRG-APP-000177', 'SRG-APP-000185', 'SRG-APP-000186', 'SRG-APP-000190', 'SRG-APP-000315', 'SRG-APP-000316', 'SRG-APP-000391', 'SRG-APP-000392', 'SRG-APP-000402', 'SRG-APP-000403']
  tag 'documentable'
  tag legacy: ['SV-102205', 'V-92103']
  tag cci: ['CCI-000056', 'CCI-000166', 'CCI-000187', 'CCI-000768', 'CCI-000766', 'CCI-000767', 'CCI-000764', 'CCI-000765', 'CCI-001133', 'CCI-000877', 'CCI-000879', 'CCI-001941', 'CCI-001953', 'CCI-001954', 'CCI-002009', 'CCI-002010', 'CCI-002314', 'CCI-002322']
  tag nist: ['AC-11 b', 'AU-10', 'IA-5 (2) (a) (2)', 'IA-2 (4)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2', 'IA-2 (1)', 'SC-10', 'MA-4 c', 'MA-4 e', 'IA-2 (8)', 'IA-2 (12)', 'IA-2 (12)', 'IA-8 (1)', 'IA-8 (1)', 'AC-17 (1)', 'AC-17 (9)']
end

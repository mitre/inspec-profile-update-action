control 'SV-81507' do
  title 'Common Access Card (CAC)-based authentication must be enforced on the Tanium Server for authentication for local access with privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following.

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This not only meets a common requirement in the Federal space but adds a critical layer of security to the user authentication process.'
  desc 'check', 'Access the Tanium server interactively and log on as an Administrator.

Run regedit as Administrator.

Navigate to HKLM\\Software\\Wow6432Node\\Tanium\\Tanium Server.

Validate the value for REG_DWORD "ForceSOAPSSLClientCert" is set to "1".

Navigate to HKLM\\Software\\Wow6432Node\\Tanium\\Tanium Server

Validate the following keys exist and are configured:
REG_SZ "ClientCertificateAuthField"

For example:
X509v3 Subject Alternative Name.
REG_SZ "ClientCertificateAuthRegex"

For example-DoD: 
.*\\:\\s*([^@]+)@.*$
     Note: This regex should be valid for any Subject Alternative Name entry.
REG_SZ "ClientCertificateAuth"
     Note: This registry value defines which certificate file to use for authentication.

For example:
C:\\Program Files\\Tanium\\Tanium Server\\dod.pem
REG_SZ "cac_ldap_server_url"
     Note: This registry value requires that Tanium validate every CAC/PIV authentication attempt with AD to determine the state of the account that’s logging in. It must use the syntax of LDAP://<AD instance FQDN>

If the value for REG_DWORD "ForceSOAPSSLClientCert" is not set to "1" and the remaining registry values are not configured, this is a finding.'
  desc 'fix', 'Use the vendor documentation titled "Enabling SmartCard Authentication in Tanium 6.5+" to implement correct configuration settings for this requirement.

Vendor documentation can be downloaded from the following URL: https://kb.tanium.com/Smart_Card_Authentication.'
  impact 0.7
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67653r2_chk'
  tag severity: 'high'
  tag gid: 'V-67017'
  tag rid: 'SV-81507r2_rule'
  tag stig_id: 'TANS-CN-000012'
  tag gtitle: 'SRG-APP-000151'
  tag fix_id: 'F-73117r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end

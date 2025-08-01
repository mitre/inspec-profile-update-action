control 'SV-253828' do
  title 'Multifactor authentication must be enabled and enforced on the Tanium Server for all access and all accounts.'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following.

1. Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and
2. Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

'
  desc 'check', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> WOW6432Node >> Tanium >> Tanium Server.

5. Validate the value for REG_DWORD "ForceSOAPSSLClientCert" is set to "1".

6. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> WOW6432Node >> Tanium >> Tanium Server.

7. Validate the following keys exist and are configured:

REG_SZ "ClientCertificateAuthField"
For example:
X509v3 Subject Alternative Name

REG_SZ "ClientCertificateAuthRegex"
For example-DoD:
.+?Name:\\s*?(\\S+@[._a-zA-Z0-9]+).*
Note: This regex may vary.

REG_SZ "ClientCertificateAuth"
For example:
E:\\Program Files\\Tanium\\Tanium Server\\cac.pem

REG_SZ "TrustedHostList"
For example:
127.0.0.1 (for IPv4) and [::1] (for IPv6)

If the value for REG_DWORD "ForceSOAPSSLClientCert" is not set to "1" and the remaining required registry values are not configured, this is a finding.'
  desc 'fix', 'Use the vendor documentation titled "Smart card authentication" to implement correct configuration settings for this requirement.

Vendor documentation can be downloaded from https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/smart_card_authentication.html?Highlight=cac.

1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> WOW6432Node >> Tanium >> Tanium Server.

5. Configure the value for REG_DWORD "ForceSOAPSSLClientCert" to "1".

6. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> WOW6432Node >> Tanium >> Tanium Server.

7. Configure the following keys:

REG_SZ "ClientCertificateAuthField"
For example:
X509v3 Subject Alternative Name

REG_SZ "ClientCertificateAuthRegex"
For example-DoD:
.+?Name:\\s*?(\\S+@[._a-zA-Z0-9]+).*
Note: This regex may vary.

REG_SZ "ClientCertificateAuth"
For example:
E:\\Program Files\\Tanium\\Tanium Server\\cac.pem

REG_SZ "TrustedHostList"
For example:
Append 127.0.0.1 (for IPv4) and [::1] (for IPv6)'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57280r842510_chk'
  tag severity: 'medium'
  tag gid: 'V-253828'
  tag rid: 'SV-253828r858412_rule'
  tag stig_id: 'TANS-CN-000027'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-57231r842511_fix'
  tag satisfies: ['SRG-APP-000080; SRG-APP-000403; SRG-APP-000156; SRG-APP-000005; SRG-APP-000150; SRG-APP-000152']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-000056', 'CCI-000166', 'CCI-000766', 'CCI-000768', 'CCI-001941', 'CCI-002010']
  tag nist: ['IA-2', 'AC-11 b', 'AU-10', 'IA-2 (2)', 'IA-2 (4)', 'IA-2 (8)', 'IA-8 (1)']
end
